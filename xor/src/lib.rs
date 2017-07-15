use std::io::{Read};

pub fn repeated_xor<R: Read, S: Read>(bytes1: R, bytes2: S) -> Vec<u8> {
    let repeated: Vec<u8> = bytes2
        .bytes()
        .map(|b| b.unwrap())
        .collect();

    bytes1
        .bytes()
        .map(|b| b.unwrap())
        .zip(repeated.into_iter().cycle())
        .map(|(b1, b2)| b1^b2)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader};

    #[test]
    fn single_byte_against_signle_byte() {
        let input = &[0x65][..];
        let xor_bytes = &[0xd1][..];

        assert_eq!(
            repeated_xor(BufReader::new(input), BufReader::new(xor_bytes)),
            vec![0xb4]);
    }

    #[test]
    fn longer_bytes_against_shorter_bytes() {
        let input = &[0x65, 0x21, 0xfa][..];
        let xor_bytes = &[0xd1, 0x03][..];

        assert_eq!(
            repeated_xor(BufReader::new(input), BufReader::new(xor_bytes)),
            vec![0xb4, 0x22, 0x2b]);
    }

    #[test]
    fn shorter_bytes_against_longer_bytes() {
        let input = &[0xd1, 0x03][..];
        let xor_bytes = &[0x65, 0x21, 0xfa][..];

        assert_eq!(
            repeated_xor(BufReader::new(input), BufReader::new(xor_bytes)),
            vec![0xb4, 0x22]);
    }

    #[test]
    fn same_size_bytes() {
        let input = &[0xd1, 0x03, 0xbf][..];
        let xor_bytes = &[0x65, 0x21, 0xfa][..];

        assert_eq!(
            repeated_xor(BufReader::new(input), BufReader::new(xor_bytes)),
            vec![0xb4, 0x22, 0x45]);
    }
}
