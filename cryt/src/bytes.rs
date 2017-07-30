pub fn hamming_distance(input1: &[u8], input2: &[u8]) -> u32 {
    input1
        .iter()
        .zip(input2.iter().cycle())
        .map(|(&b1, &b2)| b1^b2)
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

    #[test]
    fn test_hamming_distance() {
        let input1 = "this is a test".as_bytes();
        let input2 = "wokka wokka!!!".as_bytes();

        assert_eq!(hamming_distance(&input1, &input2), 37);
    }
}
