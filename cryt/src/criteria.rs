use std::collections::HashSet;
use std::iter::FromIterator;

pub type BytesCriterion = Fn(&[u8]) -> f32;

const TEXT_BYTES: [u8; 59] = ['a' as u8, 'b' as u8, 'c' as u8, 'd' as u8, 'e' as u8, 'f' as u8, 'g' as u8, 'h' as u8, 'i' as u8, 'j' as u8, 'k' as u8, 'l' as u8, 'm' as u8, 'n' as u8, 'o' as u8, 'p' as u8, 'q' as u8, 'r' as u8, 's' as u8, 't' as u8, 'u' as u8, 'v' as u8, 'w' as u8, 'x' as u8, 'y' as u8, 'z' as u8, 'A' as u8, 'B' as u8, 'C' as u8, 'D' as u8, 'E' as u8, 'F' as u8, 'G' as u8, 'H' as u8, 'I' as u8, 'J' as u8, 'K' as u8, 'L' as u8, 'M' as u8, 'N' as u8, 'O' as u8, 'P' as u8, 'Q' as u8, 'R' as u8, 'S' as u8, 'T' as u8, 'U' as u8, 'V' as u8, 'W' as u8, 'X' as u8, 'Y' as u8, 'Z' as u8, ' ' as u8, ',' as u8, '.' as u8, '\'' as u8, '!' as u8, ';' as u8, ':' as u8];

pub fn printable_bytes(bytes: &[u8]) -> f32 {
    bytes
        .iter()
        .filter(|&&b| b >= 0x20 && b <= 0x7e)
        .collect::<Vec<_>>()
        .len() as f32 / (bytes.len() as f32)
}

pub fn text_bytes(bytes: &[u8]) -> f32 {
    let set: HashSet<u8> = HashSet::from_iter(TEXT_BYTES.iter().cloned());
    bytes
        .iter()
        .filter(|&b| set.contains(b))
        .collect::<Vec<_>>()
        .len() as f32 / bytes.len() as f32
        
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_printable_bytes() {
        let input = vec!['a' as u8, 'b' as u8, 0x01, 0x15, 'c' as u8];
        assert_eq!(printable_bytes(&input), 3.0/5.0);
    }

    #[test]
    fn test_text_bytes() {
        let input = "h el.l'o$& bye! bye#@".as_bytes();
        assert_eq!(text_bytes(&input[..].to_vec()), 17.0/21.0);
    }
}
