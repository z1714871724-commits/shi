//! A compact VT100/VT220-ish terminal buffer.
//!
//! Character-based grid: each cell holds one `char`, so multibyte glyphs
//! (Nerd Font icons, CJK, emoji) render correctly instead of corrupting the
//! layout. Handles the escape sequences real shells emit most often (cursor
//! movement, line/screen erase, SGR colour stripping, OSC title,
//! insert/delete). Not a full xterm; wide glyphs are treated as one column.

const MAX_ROWS: usize = 4000;

pub struct TerminalBuffer {
    rows: Vec<Vec<char>>,
    cur_row: usize,
    cur_col: usize,
    cols: usize,
    state: State,
    params: String,
    osc_buf: String,
    height: usize,
    scrollback: Vec<Vec<char>>,
    pending: Vec<u8>, // incomplete UTF-8 carried across feed() calls
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Ground,
    Esc,
    Csi,
    Osc,
    Charset,
}

impl TerminalBuffer {
    pub fn new(cols: usize, rows: usize) -> Self {
       let rows_init = rows.max(1);
        let mut buf = Self {
           rows: (0..rows_init).map(|_| Vec::new()).collect(),
            cur_row: 0,
            cur_col: 0,
            cols,
            height: rows_init,
            scrollback: Vec::new(),
            state: State::Ground,
            params: String::new(),
            osc_buf: String::new(),
            pending: Vec::new(),
        };
        buf.ensure_row(0);
        buf
    }


    pub fn resize(&mut self, cols: usize, rows: usize) {
        self.cols = cols.max(1);
        let new_height = rows.max(1);
        // The visible screen is exactly `height` rows. When the size changes,
        // overflow rows scroll off into the scrollback and missing rows are
        // padded with blanks so the screen always has `height` entries.
        while self.rows.len() > new_height {
            self.scrollback.push(self.rows.remove(0));
            if self.cur_row > 0 {
                self.cur_row -= 1;
            }
        }
        while self.rows.len() < new_height {
            self.rows.push(Vec::new());
        }
        self.height = new_height;
        if self.cur_row >= self.height {
            self.cur_row = self.height - 1;
        }
        self.cap_total();
    }

    /// Current grid width in columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Feed raw bytes from the SSH channel. UTF-8 is decoded incrementally;
    /// a partial multibyte sequence at the end is buffered for the next call.
    pub fn feed(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        let mut i = 0;
        let bytes = std::mem::take(&mut self.pending);
        while i < bytes.len() {
            let b = bytes[i];
            let len = utf8_len(b);
            if len == 0 {
                // invalid lead byte
                self.feed_char('\u{FFFD}');
                i += 1;
                continue;
            }
            if i + len > bytes.len() {
                break; // incomplete, keep for next feed
            }
            match std::str::from_utf8(&bytes[i..i + len]) {
                Ok(s) => {
                    for c in s.chars() {
                        self.feed_char(c);
                    }
                }
                Err(_) => self.feed_char('\u{FFFD}'),
            }
            i += len;
        }
        self.pending = bytes[i..].to_vec();
    }

    fn feed_char(&mut self, c: char) {
        match self.state {
            State::Ground => self.ground(c),
            State::Esc => self.esc(c),
            State::Csi => self.csi(c),
            State::Osc => self.osc(c),
            State::Charset => {
                self.state = State::Ground;
            }
        }
    }

    fn ground(&mut self, c: char) {
        match c {
            '\u{1b}' => self.state = State::Esc,
            '\u{07}' => { /* BEL */ }
            '\u{08}' => self.backspace(),
            '\t' => self.tab(),
            '\n' | '\u{0b}' | '\u{0c}' => self.line_feed(),
            '\r' => self.cur_col = 0,
            '\0' => {}
            _ => self.put(c),
        }
    }

    fn esc(&mut self, c: char) {
        match c {
            '[' => {
                self.params.clear();
                self.state = State::Csi;
            }
            ']' => {
                self.osc_buf.clear();
                self.state = State::Osc;
            }
            '(' | ')' | '*' | '+' => self.state = State::Charset,
            '7' | '8' => self.state = State::Ground,
            'D' => {
                self.line_feed();
                self.state = State::Ground;
            }
            'E' => {
                self.cur_col = 0;
                self.line_feed();
                self.state = State::Ground;
            }
            'M' => {
                self.reverse_index();
                self.state = State::Ground;
            }
            'c' => {
                self.reset();
                self.state = State::Ground;
            }
            _ => self.state = State::Ground,
        }
    }

    fn csi(&mut self, c: char) {
        if ('\u{30}'..='\u{3f}').contains(&c) || ('\u{20}'..='\u{2f}').contains(&c) {
            self.params.push(c);
            return;
        }
        if ('\u{40}'..='\u{7e}').contains(&c) {
            self.csi_dispatch(c);
        }
        self.state = State::Ground;
        self.params.clear();
    }

    fn osc(&mut self, c: char) {
        if c == '\u{07}' {
            self.state = State::Ground;
            self.osc_buf.clear();
        } else if c == '\u{1b}' {
            // ESC likely starts ST (ESC \)
            self.state = State::Esc;
            self.osc_buf.clear();
        } else {
            self.osc_buf.push(c);
        }
    }

    fn params_list(&self) -> Vec<i64> {
        self.params
            .split([';', ':'])
            .filter_map(|p| p.parse::<i64>().ok())
            .collect()
    }

    fn param(&self, idx: usize, default: i64) -> i64 {
        self.params_list()
            .get(idx)
            .copied()
            .unwrap_or(default)
            .max(0)
    }

    fn csi_dispatch(&mut self, final_byte: char) {
        let private = self.params.starts_with('?');
        match final_byte {
            'A' => self.move_cursor(0, -self.param(0, 1)),
            'B' => self.move_cursor(0, self.param(0, 1)),
            'C' => self.move_cursor(self.param(0, 1), 0),
            'D' => self.move_cursor(-self.param(0, 1), 0),
            'E' => {
                self.cur_col = 0;
                self.move_cursor(0, self.param(0, 1));
            }
            'F' => {
                self.cur_col = 0;
                self.move_cursor(0, -self.param(0, 1));
            }
            'G' => self.set_col(self.param(0, 1)),
            'd' => self.set_row(self.param(0, 1)),
            'H' | 'f' => {
                let r = self.param(0, 1);
                let c = self.param(1, 1);
                self.set_row(r);
                self.set_col(c);
            }
            'J' if !private => self.erase_display(self.param(0, 0) as u8),
            'K' if !private => self.erase_line(self.param(0, 0) as u8),
            'P' => self.delete_chars(self.param(0, 1) as usize),
            '@' => self.insert_chars(self.param(0, 1) as usize),
            'L' => self.insert_lines(self.param(0, 1) as usize),
            'M' => self.delete_lines(self.param(0, 1) as usize),
            'm' | 'h' | 'l' | 'n' | 'r' | 'c' | 't' | 'q' => { /* SGR / modes / etc */ }
            _ => {}
        }
    }

    fn ensure_row(&mut self, idx: usize) {
        // The screen always holds exactly `height` rows; clamp the index so a
        // stray cursor move can never grow the screen beyond its bounds.
        let idx = idx.min(self.height.saturating_sub(1));
        while self.rows.len() <= idx {
            self.rows.push(Vec::new());
        }
    }

    fn put(&mut self, c: char) {
        if self.cur_col >= self.cols {
            self.cur_col = 0;
            self.line_feed();
        }
        self.ensure_row(self.cur_row);
        let row = &mut self.rows[self.cur_row];
        while row.len() <= self.cur_col {
            row.push(' ');
        }
        row[self.cur_col] = c;
        self.cur_col += 1;
        self.trim_rows();
    }

    fn backspace(&mut self) {
        if self.cur_col > 0 {
            self.cur_col -= 1;
        }
    }

    fn tab(&mut self) {
        let next = (self.cur_col / 8 + 1) * 8;
        while self.cur_col < next {
            self.put(' ');
        }
    }

    fn line_feed(&mut self) {
        if self.cur_row + 1 >= self.height {
            // past the last screen row: scroll up (top row -> scrollback) and
            // keep the cursor on the bottom row, exactly like a real terminal.
            self.scrollback.push(self.rows.remove(0));
            self.rows.push(Vec::new());
            self.cur_row = self.height - 1;
            self.cap_total();
        } else {
            self.cur_row += 1;
            self.ensure_row(self.cur_row);
        }
    }

    fn reverse_index(&mut self) {
        if self.cur_row == 0 {
            // scroll down: drop the bottom row, insert a blank at the top
            self.rows.pop();
            self.rows.insert(0, Vec::new());
        } else {
            self.cur_row -= 1;
        }
    }

    fn move_cursor(&mut self, dcol: i64, drow: i64) {
        let new_col = (self.cur_col as i64 + dcol).max(0) as usize;
        let new_row = (self.cur_row as i64 + drow).max(0) as usize;
        self.cur_col = new_col.min(self.cols.saturating_sub(1).max(0));
        self.cur_row = new_row.min(self.height.saturating_sub(1));
        self.ensure_row(self.cur_row);
    }

    fn set_col(&mut self, col: i64) {
        self.cur_col = (col as usize)
            .saturating_sub(1)
            .min(self.cols.saturating_sub(1));
    }

    fn set_row(&mut self, row: i64) {
        self.cur_row = (row as usize)
            .saturating_sub(1)
            .min(self.height.saturating_sub(1));
        self.ensure_row(self.cur_row);
    }

    fn erase_line(&mut self, mode: u8) {
        self.ensure_row(self.cur_row);
        let row = &mut self.rows[self.cur_row];
        match mode {
            0 => {
                for i in self.cur_col..row.len() {
                    row[i] = ' ';
                }
            }
            1 => {
                let end = self.cur_col.min(row.len().saturating_sub(1));
                for i in 0..=end {
                    row[i] = ' ';
                }
            }
            2 => row.clear(),
            _ => {}
        }
    }

    fn erase_display(&mut self, mode: u8) {
        match mode {
            0 => {
                self.erase_line(0);
                for i in (self.cur_row + 1)..self.rows.len() {
                    self.rows[i].clear();
                }
            }
            1 => {
                for i in 0..self.cur_row {
                    if i < self.rows.len() {
                        self.rows[i].clear();
                    }
                }
                self.erase_line(1);
            }
            2 | 3 => {
                for row in &mut self.rows {
                    row.clear();
                }
                self.cur_row = 0;
                self.cur_col = 0;
            }
            _ => {}
        }
    }

    fn delete_chars(&mut self, n: usize) {
        self.ensure_row(self.cur_row);
        let row = &mut self.rows[self.cur_row];
        let n = n.min(row.len().saturating_sub(self.cur_col));
        for _ in 0..n {
            if self.cur_col < row.len() {
                row.remove(self.cur_col);
            }
        }
    }

    fn insert_chars(&mut self, n: usize) {
        self.ensure_row(self.cur_row);
        let row = &mut self.rows[self.cur_row];
        let spaces = vec![' '; n];
        for (k, s) in spaces.into_iter().enumerate() {
            row.insert(self.cur_col + k, s);
        }
    }

    fn insert_lines(&mut self, n: usize) {
        self.ensure_row(self.cur_row);
        for _ in 0..n {
            self.rows.insert(self.cur_row, Vec::new());
        }
        // keep the screen at `height` rows; lines pushed past the bottom drop off
        while self.rows.len() > self.height {
            self.rows.pop();
        }
    }

    fn delete_lines(&mut self, n: usize) {
        self.ensure_row(self.cur_row);
        let n = n.min(self.rows.len().saturating_sub(self.cur_row));
        for _ in 0..n {
            if self.cur_row < self.rows.len() {
                self.rows.remove(self.cur_row);
            }
        }
        // restore the screen height with blank rows at the bottom
        while self.rows.len() < self.height {
            self.rows.push(Vec::new());
        }
        self.ensure_row(self.cur_row);
    }

    fn trim_rows(&mut self) {
        // kept for API stability; capping now happens in `cap_total`.
        self.cap_total();
    }

    /// Cap the combined scrollback + screen to `MAX_ROWS`, dropping the oldest
    /// scrollback rows. The screen itself is always `height` rows, so only the
    /// scrollback ever needs trimming.
    fn cap_total(&mut self) {
        if self.scrollback.len() > MAX_ROWS {
            let drop = self.scrollback.len() - MAX_ROWS;
            self.scrollback.drain(..drop);
        }
    }

    pub fn reset(&mut self) {
        self.rows = (0..self.height).map(|_| Vec::new()).collect();
        self.scrollback.clear();
        self.cur_row = 0;
        self.cur_col = 0;
    }

    /// Render the current screen as a UTF-8 string: exactly `height` rows,
    /// top to bottom, with per-line trailing whitespace trimmed. Trailing
    /// blank rows are preserved so the remote shell's absolute row
    /// coordinates (1..=height) map 1:1 to visual rows - this is what keeps
    /// cursor movement, line editing, tab completion and TUIs aligned.
    /// Scrollback is retained internally for a future scroll-up view but is
    /// not part of the live render, which always mirrors the fixed screen the
    /// shell thinks it is drawing on.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(self.height * (self.cols + 1));
        for i in 0..self.height {
            if i < self.rows.len() {
                let s: String = self.rows[i].iter().collect();
                out.push_str(s.trim_end());
            }
            if i + 1 < self.height {
                out.push('\n');
            }
        }
        out
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_glyph_keeps_one_column() {
        let mut t = TerminalBuffer::new(20, 2);
        // a Nerd Font private-use glyph (3 bytes) followed by text
        t.feed("❯ hostname\r\n".as_bytes());
        // render() is the fixed 2-row screen: row 0 holds the prompt, row 1 is
        // blank, so a trailing newline separates them.
        assert_eq!(t.render(), "❯ hostname\n");
    }

    #[test]
    fn strips_color_codes() {
        let mut t = TerminalBuffer::new(40, 2);
        t.feed(b"\x1b[31mred\x1b[0m text");
        assert_eq!(t.render(), "red text\n");
    }

    #[test]
    fn handles_crlf() {
        let mut t = TerminalBuffer::new(40, 4);
        t.feed(b"a\r\nb\r\nc");
        // 4-row screen: "a","b","c","" -> three newlines join them.
        assert_eq!(t.render(), "a\nb\nc\n");
    }

    #[test]
    fn clear_screen() {
        let mut t = TerminalBuffer::new(40, 4);
        t.feed(b"abc\x1b[2J");
        // a cleared 4-row screen is four blank lines (three newlines).
        assert_eq!(t.render(), "\n\n\n");
    }

    #[test]
    fn partial_utf8_is_buffered() {
        let mut t = TerminalBuffer::new(20, 2);
        let bytes = "❯".as_bytes(); // 3 bytes
        t.feed(&bytes[..1]); // incomplete
        // nothing written yet: both screen rows are blank.
        assert_eq!(t.render(), "\n");
        t.feed(&bytes[1..]);
        assert_eq!(t.render(), "❯\n");
    }
}

#[cfg(test)]
mod right_prompt_tests {
    use super::*;

    /// A zsh/starship right prompt is drawn by jumping the cursor to the right
    /// side of the line (CHA / cursor-forward) and writing the right segments.
    /// It must stay on the same line as the left prompt, not wrap.
    #[test]
    fn right_prompt_stays_on_one_line() {
        let mut t = TerminalBuffer::new(100, 4);
        // left prompt: "~ ❯ "  (❯ is a 3-byte UTF-8 glyph, 1 cell)
        t.feed(b"~ \xe2\x9d\xaf ");
        // zsh moves cursor to column 70 (1-indexed) via CHA
        t.feed(b"\x1b[70G");
        // right prompt segment
        t.feed(b"system host 10:51:50");
        let r = t.render();
        // the right prompt must share the first screen row with the left one.
        let first = r.lines().next().unwrap();
        assert!(first.contains("~ \u{276f}"), "left prompt missing: {r:?}");
        assert!(
            first.contains("system host 10:51:50"),
            "right prompt missing: {r:?}"
        );
    }

    /// CUF (cursor-forward) by a large amount clamps to the last column but
    /// must not itself insert a newline.
    #[test]
    fn cursor_forward_clamps_without_wrap() {
        let mut t = TerminalBuffer::new(40, 4);
        t.feed(b"ab");
        t.feed(b"\x1b[999C"); // jump far right -> clamps to col 39
        t.feed(b"Z");
        let r = t.render();
        let first = r.lines().next().unwrap();
        assert!(first.starts_with("ab"), "left text lost: {r:?}");
        assert!(first.contains('Z'), "right char lost: {r:?}");
    }
}

#[cfg(test)]
mod scroll_tests {
    use super::*;

    /// When the cursor line-feeds past the last screen row the top row must
    /// scroll into the scrollback instead of the screen growing unboundedly.
    /// This keeps the shell's screen model in sync with the buffer.
    #[test]
    fn scrolls_at_bottom_instead_of_growing() {
        let mut t = TerminalBuffer::new(10, 3);
        t.feed(b"line1\r\nline2\r\nline3\r\nline4");
        // render() shows the current 3-row screen only; line1 scrolled into
        // the (internal, not-yet-rendered) scrollback.
        let rendered = t.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(
            lines,
            &["line2", "line3", "line4"],
            "screen rows wrong: {lines:?}"
        );
    }
}

#[cfg(test)]
mod cursor_sync_tests {
    use super::*;

    /// After the screen scrolls, an absolute cursor-position request (CUP to
    /// row 1) must address the top of the *current screen*, not a row that has
    /// already scrolled into the scrollback. This is the desync that previously
    /// made the prompt render in the middle of the terminal.
    #[test]
    fn absolute_cursor_targets_current_screen_after_scroll() {
        let mut t = TerminalBuffer::new(10, 3);
        t.feed(b"line1\r\nline2\r\nline3\r\nline4");
        // move to row 1, col 1 (top of the visible screen) and overwrite
        t.feed(b"\x1b[1;1HXXXX");
        let r = t.render();
        let lines: Vec<&str> = r.lines().collect();
        // CUP row 1 targets the top of the CURRENT screen (line2's row), so
        // XXXX overwrites the start of line2; line1 stays in the scrollback.
        assert_eq!(lines.len(), 3, "screen height: {r:?}");
        assert!(lines[0].starts_with("XXXX"), "cup hit wrong row: {r:?}");
        assert_eq!(lines[1], "line3", "screen row 2 wrong: {r:?}");
        assert_eq!(lines[2], "line4", "screen row 3 wrong: {r:?}");
    }
}
