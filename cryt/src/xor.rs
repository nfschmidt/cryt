use bytes;

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

pub fn single_byte_decrypted<R: Read>(bytes: R, scorer: fn(&Vec<u8>) -> f32) -> (u8, f32, Vec<u8>) {
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

    (key, score, decrypted)
}

pub fn repeated_xor_keysize<R: Read>(bytes: R, min_length: u32, max_length: u32, criterion: fn(&Vec<u8>, u32) -> f32) -> Vec<(u32, f32)> {
    let input: Vec<u8> = bytes
        .bytes()
        .map(|b| b.unwrap())
        .collect();

    let mut results = (min_length..max_length + 1)
        .map(|l| (l, criterion(&input, l)) )
        .collect::<Vec<_>>();

    results.sort_by(|&(_, s1), &(_, s2)| s2.partial_cmp(&s1).unwrap());

    results
}

pub fn hamming_distance_criterion(input: &Vec<u8>, size: u32) -> f32 {
    let mut chunk_pairs_count = 0;
    let mut distances_sum = 0;
    for chunk_pair in input.chunks(size as usize).collect::<Vec<_>>().chunks(2) {
        if chunk_pair.len() != 2 || chunk_pair[1].len() != size as usize {
            break;
        }

        distances_sum += bytes::hamming_distance(chunk_pair[0], chunk_pair[1]);
        chunk_pairs_count += 1;
    }

    1.0 / (distances_sum as f32 / chunk_pairs_count as f32 / size as f32)
}

pub fn decrypted_repeated_xor<R: Read>(input: R, min_key_size: u32, max_key_size: u32, keysize_criterion: fn (&Vec<u8>, u32) -> f32, xor_criterion: fn (&Vec<u8>) -> f32) -> (Vec<u8>, Vec<u8>) {

    let input_bytes: Vec<u8> = input.bytes().map(|b| b.unwrap()).collect();
    let keysizes = repeated_xor_keysize(&input_bytes[..], min_key_size, max_key_size, keysize_criterion);
    let keysize = keysizes[0].0;

    let mut key = Vec::new();

    for nth_position in 0..keysize {
        let block: Vec<u8> = input_bytes
            .iter()
            .enumerate()
            .filter(|x| x.0 as u32 % keysize == nth_position)
            .map(|(_, &b)| b)
            .collect();

        let (block_key, _, _) = single_byte_decrypted(&block[..], xor_criterion);
        key.push(block_key);
    }

    let result = repeated_xor(&input_bytes[..], &key[..]);
    (key, result)
}

#[cfg(test)]
mod tests {
    use bytes;

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

        let (key, score, decrypted) = single_byte_decrypted(encrypted, scorer);

        assert_eq!(key, 'x' as u8);
        assert_eq!(score, 15.0);
        assert_eq!(decrypted, input);
    }

    #[test]
    fn test_repeated_xor_keysize() {
        fn keysize_scorer(_: &Vec<u8>, keysize: u32) -> f32 {
            if keysize == 8 {
                2.0
            } else {
                1.0 / keysize as f32
            }
        }

        assert_eq!(
            repeated_xor_keysize(BufReader::new("test".as_bytes()), 1, 10, keysize_scorer),
            [(8, 2.0), (1, 1.0/1.0), (2, 1.0/2.0), (3, 1.0/3.0), (4, 1.0/4.0), (5, 1.0/5.0), (6, 1.0/6.0), (7, 1.0/7.0), (9, 1.0/9.0), (10, 1.0/10.0)])
    }

    #[test]
    fn hamming_distance_criterion_with_input_multiple_of_size() {
        let input = Vec::from("some random text in eng!".as_bytes());
        let score = hamming_distance_criterion(&input, 6);

        let expected = 1.0 / (((
            bytes::hamming_distance(BufReader::new("some r".as_bytes()), BufReader::new("andom ".as_bytes())) +
            bytes::hamming_distance(BufReader::new("text i".as_bytes()), BufReader::new("n eng!".as_bytes()))
        ) as f32 / 2.0) / 6.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn hamming_distance_criterion_with_input_not_multiple_of_size() {
        let input = Vec::from("some random text!!XX".as_bytes());
        let score = hamming_distance_criterion(&input, 3);

        let expected = 1.0 / (((
            bytes::hamming_distance(BufReader::new("som".as_bytes()), BufReader::new("e r".as_bytes())) +
            bytes::hamming_distance(BufReader::new("and".as_bytes()), BufReader::new("om ".as_bytes())) +
            bytes::hamming_distance(BufReader::new("tex".as_bytes()), BufReader::new("t!!".as_bytes()))
        ) as f32 / 3.0) / 3.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn hamming_distance_criterion_with_input_pairs_not_multiple_of_2() {
        let input = Vec::from("some random tex!".as_bytes());
        let score = hamming_distance_criterion(&input, 3);

        let expected = 1.0 / (((
            bytes::hamming_distance(BufReader::new("som".as_bytes()), BufReader::new("e r".as_bytes())) +
            bytes::hamming_distance(BufReader::new("and".as_bytes()), BufReader::new("om ".as_bytes()))
        ) as f32 / 2.0) / 3.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn repeated_xor_decrypted() {
        let plain_text = "this text is encrypted with repeated xor".as_bytes();
        let key = "SeCreT".as_bytes();
        let input = repeated_xor(
            BufReader::new(plain_text),
            BufReader::new(key));

        fn keysize_scorer(_: &Vec<u8>, keysize: u32) -> f32 {
            if keysize == "SeCreT".as_bytes().len() as u32 {
                2.0
            } else {
                1.0 / keysize as f32
            }
        }

        fn xor_scorer(input: &Vec<u8>) -> f32 {
            input
                .iter()
                .filter(|&&b| "this text is encrypted with repeated xor"
                            .as_bytes()
                            .iter()
                            .any(|&c| c == b))
                .count() as f32
        }

        let (resultkey, decrypted) = decrypted_repeated_xor(&input[..], 1, 15, keysize_scorer, xor_scorer);

        assert_eq!(Vec::from(key), resultkey);
        assert_eq!(Vec::from(plain_text), decrypted);
    }
}
