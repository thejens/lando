//! Minimal JSON for the control-plane RPCs: a buffer writer and a field
//! extractor, both `no_std` and allocation-free.
//!
//! The extractor here deliberately works on a **complete** buffer. That is
//! correct for `RegisterResponse`, which is a few hundred bytes, and wrong for
//! `MapResponse`, which can be megabytes and must never be buffered whole. The
//! map stage needs a resumable tokenizer that keeps only the current token in
//! memory; this module is not it, and should not be pressed into that role.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    ShortBuffer,
    /// Input ended mid-value.
    Truncated,
    /// Input is not valid JSON in a way that matters to us.
    Malformed,
}

// ---------------------------------------------------------------- writing

/// Builds JSON into a caller-supplied buffer, tracking separators so callers
/// never hand-write a comma.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    /// True when the next value or key must be preceded by a comma.
    needs_comma: bool,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            needs_comma: false,
        }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), JsonError> {
        if self.pos + bytes.len() > self.buf.len() {
            return Err(JsonError::ShortBuffer);
        }
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn byte(&mut self, b: u8) -> Result<(), JsonError> {
        self.raw(&[b])
    }

    fn separate(&mut self) -> Result<(), JsonError> {
        if self.needs_comma {
            self.byte(b',')?;
        }
        Ok(())
    }

    pub fn begin_object(&mut self) -> Result<(), JsonError> {
        self.separate()?;
        self.needs_comma = false;
        self.byte(b'{')
    }

    pub fn end_object(&mut self) -> Result<(), JsonError> {
        self.needs_comma = true;
        self.byte(b'}')
    }

    pub fn begin_array(&mut self) -> Result<(), JsonError> {
        self.separate()?;
        self.needs_comma = false;
        self.byte(b'[')
    }

    pub fn end_array(&mut self) -> Result<(), JsonError> {
        self.needs_comma = true;
        self.byte(b']')
    }

    /// Writes an object key. The following value call supplies the value.
    pub fn key(&mut self, k: &str) -> Result<(), JsonError> {
        self.separate()?;
        self.write_string(k)?;
        self.needs_comma = false;
        self.byte(b':')
    }

    pub fn str_value(&mut self, v: &str) -> Result<(), JsonError> {
        self.separate()?;
        self.write_string(v)?;
        self.needs_comma = true;
        Ok(())
    }

    /// Writes bytes verbatim as a value. Use for already-rendered JSON.
    pub fn raw_value(&mut self, v: &[u8]) -> Result<(), JsonError> {
        self.separate()?;
        self.raw(v)?;
        self.needs_comma = true;
        Ok(())
    }

    pub fn u64_value(&mut self, mut v: u64) -> Result<(), JsonError> {
        self.separate()?;
        let mut digits = [0u8; 20];
        let s = if v == 0 {
            digits[0] = b'0';
            &digits[..1]
        } else {
            let mut i = 20;
            while v > 0 {
                i -= 1;
                digits[i] = b'0' + (v % 10) as u8;
                v /= 10;
            }
            digits.copy_within(i..20, 0);
            &digits[..20 - i]
        };
        self.raw(s)?;
        self.needs_comma = true;
        Ok(())
    }

    pub fn bool_value(&mut self, v: bool) -> Result<(), JsonError> {
        self.separate()?;
        self.raw(if v { b"true" } else { b"false" })?;
        self.needs_comma = true;
        Ok(())
    }

    pub fn field_str(&mut self, k: &str, v: &str) -> Result<(), JsonError> {
        self.key(k)?;
        self.str_value(v)
    }

    pub fn field_u64(&mut self, k: &str, v: u64) -> Result<(), JsonError> {
        self.key(k)?;
        self.u64_value(v)
    }

    pub fn field_bool(&mut self, k: &str, v: bool) -> Result<(), JsonError> {
        self.key(k)?;
        self.bool_value(v)
    }

    /// Emits a quoted, escaped JSON string.
    ///
    /// Control characters must be escaped or the server's decoder rejects the
    /// whole request — a real hazard because hostnames and auth keys are
    /// caller-supplied and this runs on a device where the input came from a
    /// USB provisioning blob.
    fn write_string(&mut self, s: &str) -> Result<(), JsonError> {
        self.byte(b'"')?;
        for &b in s.as_bytes() {
            match b {
                b'"' => self.raw(b"\\\"")?,
                b'\\' => self.raw(b"\\\\")?,
                b'\n' => self.raw(b"\\n")?,
                b'\r' => self.raw(b"\\r")?,
                b'\t' => self.raw(b"\\t")?,
                0x00..=0x1f => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.raw(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(b >> 4) as usize],
                        HEX[(b & 0xf) as usize],
                    ])?;
                }
                _ => self.byte(b)?,
            }
        }
        self.byte(b'"')
    }
}

// ---------------------------------------------------------------- reading

/// A JSON value located inside a buffer, returned without copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    /// String contents with escapes still encoded — use [`unescape`] if the
    /// field can contain them. Most control-plane fields cannot.
    Str(&'a str),
    Number(&'a str),
    Bool(bool),
    Null,
    /// A nested object or array, as its raw slice.
    Raw(&'a [u8]),
}

impl<'a> Value<'a> {
    pub fn as_str(&self) -> Option<&'a str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// True for a string that is present but empty — the control plane's way
    /// of saying "no error" and "no auth URL needed".
    pub fn is_empty_str(&self) -> bool {
        matches!(self, Value::Str(s) if s.is_empty())
    }
}

/// Looks up a field of the top-level JSON object.
///
/// Nested objects and arrays are skipped over rather than descended into, so a
/// key that also appears inside a nested value cannot shadow the real one.
pub fn field<'a>(json: &'a [u8], want: &str) -> Result<Option<Value<'a>>, JsonError> {
    let mut p = Parser { s: json, i: 0 };
    p.skip_ws();
    p.expect(b'{')?;
    p.skip_ws();
    if p.peek() == Some(b'}') {
        return Ok(None);
    }
    loop {
        p.skip_ws();
        let key = p.parse_string()?;
        p.skip_ws();
        p.expect(b':')?;
        p.skip_ws();
        let value = p.parse_value()?;
        if key == want {
            return Ok(Some(value));
        }
        p.skip_ws();
        match p.next() {
            Some(b',') => continue,
            Some(b'}') => return Ok(None),
            _ => return Err(JsonError::Malformed),
        }
    }
}

/// Iterates the elements of a JSON array without copying them.
///
/// Nested structures are skipped whole, so an element containing arrays or
/// objects is returned intact rather than being descended into.
pub fn elements(raw: &[u8]) -> Elements<'_> {
    Elements {
        p: Parser { s: raw, i: 0 },
        started: false,
        done: false,
    }
}

pub struct Elements<'a> {
    p: Parser<'a>,
    started: bool,
    done: bool,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Value<'a>;

    fn next(&mut self) -> Option<Value<'a>> {
        if self.done {
            return None;
        }
        if !self.started {
            self.started = true;
            self.p.skip_ws();
            if self.p.next() != Some(b'[') {
                self.done = true;
                return None;
            }
        } else {
            self.p.skip_ws();
            match self.p.next() {
                Some(b',') => {}
                _ => {
                    self.done = true;
                    return None;
                }
            }
        }
        self.p.skip_ws();
        if self.p.peek() == Some(b']') {
            self.done = true;
            return None;
        }
        match self.p.parse_value() {
            Ok(v) => Some(v),
            Err(_) => {
                self.done = true;
                None
            }
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let b = self.peek();
        if b.is_some() {
            self.i += 1;
        }
        b
    }

    fn expect(&mut self, b: u8) -> Result<(), JsonError> {
        if self.next() == Some(b) {
            Ok(())
        } else {
            Err(JsonError::Malformed)
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    /// Parses a quoted string, returning its contents with escapes intact.
    fn parse_string(&mut self) -> Result<&'a str, JsonError> {
        self.expect(b'"')?;
        let start = self.i;
        loop {
            match self.next().ok_or(JsonError::Truncated)? {
                b'"' => {
                    let raw = &self.s[start..self.i - 1];
                    return core::str::from_utf8(raw).map_err(|_| JsonError::Malformed);
                }
                // Skip the escaped byte so an escaped quote does not terminate.
                b'\\' => {
                    self.next().ok_or(JsonError::Truncated)?;
                }
                _ => {}
            }
        }
    }

    fn parse_value(&mut self) -> Result<Value<'a>, JsonError> {
        match self.peek().ok_or(JsonError::Truncated)? {
            b'"' => Ok(Value::Str(self.parse_string()?)),
            b'{' => Ok(Value::Raw(self.skip_nested(b'{', b'}')?)),
            b'[' => Ok(Value::Raw(self.skip_nested(b'[', b']')?)),
            b't' => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            b'f' => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            b'n' => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            _ => {
                let start = self.i;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                if self.i == start {
                    return Err(JsonError::Malformed);
                }
                core::str::from_utf8(&self.s[start..self.i])
                    .map(Value::Number)
                    .map_err(|_| JsonError::Malformed)
            }
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), JsonError> {
        if self.s.len() < self.i + lit.len() || &self.s[self.i..self.i + lit.len()] != lit {
            return Err(JsonError::Malformed);
        }
        self.i += lit.len();
        Ok(())
    }

    /// Consumes a balanced object or array, honouring strings so that a brace
    /// inside a string literal does not throw off the depth count.
    fn skip_nested(&mut self, open: u8, close: u8) -> Result<&'a [u8], JsonError> {
        let start = self.i;
        let mut depth = 0usize;
        loop {
            match self.next().ok_or(JsonError::Truncated)? {
                b'"' => {
                    self.i -= 1;
                    self.parse_string()?;
                }
                b if b == open => depth += 1,
                b if b == close => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(&self.s[start..self.i]);
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s<'a>(w: &'a Writer<'_>) -> &'a str {
        core::str::from_utf8(w.as_bytes()).unwrap()
    }

    #[test]
    fn writes_nested_objects_with_correct_commas() {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.begin_object().unwrap();
        w.field_u64("Version", 145).unwrap();
        w.field_str("NodeKey", "nodekey:ab").unwrap();
        w.key("Auth").unwrap();
        w.begin_object().unwrap();
        w.field_str("AuthKey", "tskey-auth-x").unwrap();
        w.end_object().unwrap();
        w.field_bool("Ephemeral", false).unwrap();
        w.end_object().unwrap();

        assert_eq!(
            s(&w),
            r#"{"Version":145,"NodeKey":"nodekey:ab","Auth":{"AuthKey":"tskey-auth-x"},"Ephemeral":false}"#
        );
    }

    #[test]
    fn escapes_strings() {
        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        w.str_value("a\"b\\c\nd\te").unwrap();
        assert_eq!(s(&w), r#""a\"b\\c\nd\te""#);

        let mut buf = [0u8; 128];
        let mut w = Writer::new(&mut buf);
        w.str_value("\x01").unwrap();
        assert_eq!(s(&w), r#""\u0001""#);
    }

    #[test]
    fn reports_short_buffer_rather_than_truncating() {
        let mut buf = [0u8; 4];
        let mut w = Writer::new(&mut buf);
        w.begin_object().unwrap();
        assert_eq!(w.field_str("k", "vvvvvv"), Err(JsonError::ShortBuffer));
    }

    #[test]
    fn extracts_top_level_fields() {
        let j = br#"{"User":{"ID":1},"MachineAuthorized":true,"AuthURL":"","Error":"","N":42}"#;
        assert_eq!(
            field(j, "MachineAuthorized").unwrap(),
            Some(Value::Bool(true))
        );
        assert_eq!(field(j, "AuthURL").unwrap(), Some(Value::Str("")));
        assert_eq!(field(j, "N").unwrap(), Some(Value::Number("42")));
        assert_eq!(field(j, "Missing").unwrap(), None);
        assert!(matches!(
            field(j, "User").unwrap(),
            Some(Value::Raw(b"{\"ID\":1}"))
        ));
    }

    /// A key inside a nested object must not be mistaken for a top-level one.
    #[test]
    fn nested_keys_do_not_shadow_top_level() {
        let j = br#"{"User":{"Error":"nested"},"Error":"real"}"#;
        assert_eq!(field(j, "Error").unwrap(), Some(Value::Str("real")));
    }

    /// Braces and brackets inside string literals must not confuse the depth
    /// counter — this is the classic way a hand-rolled skipper breaks.
    #[test]
    fn braces_inside_strings_are_ignored() {
        let j = br#"{"A":{"s":"}{[]"},"B":"found"}"#;
        assert_eq!(field(j, "B").unwrap(), Some(Value::Str("found")));

        let j = br#"{"A":["}","{"],"B":"found"}"#;
        assert_eq!(field(j, "B").unwrap(), Some(Value::Str("found")));
    }

    #[test]
    fn escaped_quotes_do_not_end_strings() {
        let j = br#"{"A":"x\"},\"y","B":"found"}"#;
        assert_eq!(field(j, "B").unwrap(), Some(Value::Str("found")));
        assert_eq!(field(j, "A").unwrap(), Some(Value::Str(r#"x\"},\"y"#)));
    }

    #[test]
    fn handles_empty_object_and_truncation() {
        assert_eq!(field(b"{}", "x").unwrap(), None);
        assert_eq!(field(br#"{"a":"unterminated"#, "a"), Err(JsonError::Truncated));
        assert_eq!(field(b"not json", "a"), Err(JsonError::Malformed));
    }
}
