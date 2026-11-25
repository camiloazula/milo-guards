//! Base64 (RFC 4648, with padding), how a line reaches PowerShell and how
//! its parser's answer comes back: text that holds no quote, space or line
//! break of its own, so no line can be read as part of the script.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` in base64.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(
                    ALPHABET[usize::try_from((n >> shift) & 63).unwrap_or(0)],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bytes `text` holds in base64, or `None` when it is not base64.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let text = text.as_bytes();
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (index, chunk) in text.chunks(4).enumerate() {
        let last = index + 1 == text.len() / 4;
        let padding = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - padding] {
            let value = ALPHABET.iter().position(|&a| a == c)?;
            n = (n << 6) | u32::try_from(value).ok()?;
        }
        n <<= 6 * padding;
        let bytes = n.to_be_bytes();
        out.extend_from_slice(&bytes[1..4 - padding]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_reads_back_what_it_writes() {
        for (bytes, text) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"rm -rf ~\n'x'", "cm0gLXJmIH4KJ3gn"),
        ] {
            assert_eq!(encode(bytes), text);
            assert_eq!(decode(text).as_deref(), Some(bytes));
        }
        let every: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&every)), Some(every));
    }

    #[test]
    fn what_is_not_base64_is_refused() {
        for text in ["Zg=", "Z===", "Zg==Zg==", "Zm9!", "Zm 9"] {
            assert_eq!(decode(text), None, "{text}");
        }
    }
}
