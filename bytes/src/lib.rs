use std::io::Read;

pub fn hamming_distance<R: Read, S: Read>(bytes1: R, bytes2: S) -> u32 {
    let input1: Vec<u8> = bytes1
        .bytes()
        .map(|b| b.unwrap())
        .collect();

    let input2: Vec<u8> = bytes2
        .bytes()
        .map(|b| b.unwrap())
        .collect();

    input1
        .iter()
        .zip(input2.into_iter().cycle())
        .map(|(b1, b2)| b1^b2)
        .map(|xored| bits_on(xored) as u32)
        .sum()
}

fn bits_on(b: u8) -> u8 {
    (0..8)
        .map(|i| (b >> i) & 0x01)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn test_hamming_distance() {
        let input1 = "this is a test".as_bytes();
        let input2 = "wokka wokka!!!".as_bytes();

        assert_eq!(hamming_distance(BufReader::new(input1), BufReader::new(input2)), 37);
    }
}
