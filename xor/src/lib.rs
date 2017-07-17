use std::io::{Read};

pub fn repeated_xor<R: Read, S: Read>(bytes1: R, bytes2: S) -> Vec<u8> {
    let repeated_key: Vec<u8> = bytes2
        .bytes()
        .map(|b| b.unwrap())
        .collect();

    bytes1
        .bytes()
        .map(|b| b.unwrap())
        .zip(repeated_key.into_iter().cycle())
        .map(|(b1, b2)| b1^b2)
        .collect()
}

pub fn single_byte_decrypted<R: Read>(bytes: R, scorer: fn(&Vec<u8>) -> f32) -> (u8, Vec<u8>) {
    let mut key = 0;
    let mut score = 0.0;
    let mut decrypted: Vec<u8> = vec![];

    let input = &bytes.bytes().map(|b| b.unwrap()).collect::<Vec<u8>>()[..];

    for i in 0..256 {
        let k: u16 = i; // Fix to avoid buggy overflow warning
        let result_for_key = repeated_xor(input, &[k as u8][..]);
        let new_score = scorer(&result_for_key);

        if new_score > score {
            score = new_score;
            key = k as u8;
            decrypted = result_for_key;
        }
    }

    (key, decrypted)
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

    #[test]
    fn single_byte_decryption_retuns_byte_with_highest_score() {
        let input = "eeeee English text with lots of 'e' eeeeeeee".as_bytes();
        let key = &['x' as u8][..];
        let encrypted = &repeated_xor(input, BufReader::new(key))[..];

        fn scorer(input: &Vec<u8>) -> f32 {
            input
                .into_iter()
                .filter(|&&b| b == 0x65)
                .collect::<Vec<_>>()
                .len() as f32
        }

        let (key, decrypted) = single_byte_decrypted(encrypted, scorer);

        assert_eq!(key, 'x' as u8);
        assert_eq!(decrypted, input);
    }
}
