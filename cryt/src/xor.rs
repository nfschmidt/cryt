use bytes;
use criteria::{BytesCriterion, text_bytes};

pub fn hamming_distance_criterion(input: &[u8], size: u32) -> f32 {
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

pub struct Xor<'a> {
    key: &'a [u8]
}

impl<'a> Xor<'a> {
    // Builder methods
    pub fn new(key: &'a [u8]) -> Xor<'a> {
        Xor { key: key }
    }

    // Encryption methods
    pub fn encrypt(&self, input: &[u8]) -> Vec<u8> {
        input
            .iter()
            .zip(self.key.iter().cycle())
            .map(|(b1, b2)| b1^b2)
            .collect()
    }

    pub fn decrypt(&self, input: &[u8]) -> Vec<u8> {
        self.encrypt(input)
    }
}

pub struct SingleByteAttack {
    criterion: Box<BytesCriterion>
}

impl SingleByteAttack {

    pub fn new() -> SingleByteAttack {
        SingleByteAttack{
            criterion: Box::new(text_bytes),
        }
    }

    pub fn with_criterion(mut self, bc: Box<BytesCriterion>) -> SingleByteAttack {
        self.criterion = bc;
        self
    }

    pub fn result(&self, input: &[u8]) -> (u8, f32, Vec<u8>) {
        let mut key = 0;
        let mut score = 0.0;
        let mut decrypted: Vec<u8> = vec![];

        for i in 0..256 {
            let k: u16 = i; // Fix to avoid buggy overflow warning
            let this_key = &[k as u8];
            let result_for_key = Xor::new(this_key).decrypt(input);
            let new_score = (self.criterion)(&result_for_key);

            if new_score > score {
                score = new_score;
                key = k as u8;
                decrypted = result_for_key;
            }
        }

        (key, score, decrypted)
    }
}

pub type KeysizeCriterion = Fn(&[u8], u32) -> f32;

pub struct KeysizeAttack {
    criterion: Box<KeysizeCriterion>,
    min_length: u32,
    max_length: u32,
}

impl KeysizeAttack {

    pub fn new() -> KeysizeAttack {
        KeysizeAttack {
            criterion: Box::new(hamming_distance_criterion),
            min_length: 1,
            max_length: 32,
        }
    }

    pub fn with_criterion(mut self, criterion: Box<KeysizeCriterion>) -> KeysizeAttack {
        self.criterion = criterion;
        self
    }

    pub fn with_min_length(mut self, min_length: u32) -> KeysizeAttack {
        self.min_length = min_length;
        self
    }

    pub fn with_max_length(mut self, max_length: u32) -> KeysizeAttack {
        self.max_length = max_length;
        self
    }

    pub fn result(&self, input: &[u8]) -> Vec<(u32, f32)> {
        let mut results = (self.min_length..self.max_length + 1)
            .map(|l| (l, (self.criterion)(input, l)) )
            .collect::<Vec<_>>();

        results.sort_by(|&(_, s1), &(_, s2)| s2.partial_cmp(&s1).unwrap());

        results
    }
}

pub struct RepeatedAttack {
    single_byte_attack: SingleByteAttack,
    keysize_attack: KeysizeAttack,
}

impl RepeatedAttack {
    pub fn new() -> RepeatedAttack {
        RepeatedAttack {
            single_byte_attack: SingleByteAttack::new(),
            keysize_attack: KeysizeAttack::new(),
        }
    }

    pub fn with_single_byte_attack(mut self, attack: SingleByteAttack) -> RepeatedAttack {
        self.single_byte_attack = attack;
        self
    }

    pub fn with_keysize_attack(mut self, attack: KeysizeAttack) -> RepeatedAttack {
        self.keysize_attack = attack;
        self
    }

    pub fn result(&self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let keysizes = self.keysize_attack.result(input);
        let keysize = keysizes[0].0;

        let mut key = Vec::new();

        for nth_position in 0..keysize {
            let block: Vec<u8> = input
                .iter()
                .enumerate()
                .filter(|x| x.0 as u32 % keysize == nth_position)
                .map(|(_, &b)| b)
                .collect();

            let (block_key, _, _) = self.single_byte_attack.result(&block);
            key.push(block_key);
        }

        let result = Xor::new(&key).decrypt(input);
        (key, result)
    }
}

#[cfg(test)]
mod tests {
    use bytes;

    use super::*;

    #[test]
    fn single_byte_against_single_byte() {
        let key = &[0xd1];
        let xorer = Xor::new(key);
        let input = &[0x65];

        assert_eq!(xorer.encrypt(input), vec![0xb4]);
    }

    #[test]
    fn longer_bytes_against_shorter_bytes() {
        let key = &[0xd1, 0x03];
        let xorer = Xor::new(key);
        let input = &[0x65, 0x21, 0xfa];

        assert_eq!(xorer.encrypt(input), vec![0xb4, 0x22, 0x2b]);
    }

    #[test]
    fn shorter_bytes_against_longer_bytes() {
        let key = &[0x65, 0x21, 0xfa];
        let xorer = Xor::new(key);
        let input = &[0xd1, 0x03];

        assert_eq!(xorer.encrypt(input), vec![0xb4, 0x22]);
    }

    #[test]
    fn same_size_bytes() {
        let key = &[0x65, 0x21, 0xfa];
        let xorer = Xor::new(key);
        let input = &[0xd1, 0x03, 0xbf];

        assert_eq!(xorer.encrypt(input), vec![0xb4, 0x22, 0x45]);
    }

    #[test]
    fn single_byte_decryption_retuns_byte_with_highest_score() {
        let input = "eeeee English text with lots of 'e' eeeeeeee".as_bytes();
        let key = &['x' as u8];
        let encrypted = &(Xor::new(key)).encrypt(input);

        let scorer = |i: &[u8]| {
            i
                .iter()
                .filter(|&&b| b == 'e' as u8)
                .collect::<Vec<_>>()
                .len() as f32
        };

        let attack = SingleByteAttack::new()
            .with_criterion(Box::new(scorer));

        let (key, score, decrypted) = attack.result(encrypted);

        assert_eq!(key, 'x' as u8);
        assert_eq!(score, 15.0);
        assert_eq!(decrypted, input);
    }

    #[test]
    fn test_repeated_xor_keysize() {
        let keysize_scorer = |_: &[u8], keysize| {
            if keysize == 8 {
                2.0
            } else {
                1.0 / keysize as f32
            }
        };

        let result = KeysizeAttack::new()
            .with_min_length(1)
            .with_max_length(10)
            .with_criterion(Box::new(keysize_scorer))
            .result("test".as_bytes());

        assert_eq!(
            result,
            [(8, 2.0), (1, 1.0/1.0), (2, 1.0/2.0), (3, 1.0/3.0), (4, 1.0/4.0), (5, 1.0/5.0), (6, 1.0/6.0), (7, 1.0/7.0), (9, 1.0/9.0), (10, 1.0/10.0)]
        )
    }

    #[test]
    fn hamming_distance_criterion_with_input_multiple_of_size() {
        let input = Vec::from("some random text in eng!".as_bytes());
        let score = hamming_distance_criterion(&input, 6);

        let expected = 1.0 / (((
            bytes::hamming_distance("some r".as_bytes(), "andom ".as_bytes()) +
            bytes::hamming_distance("text i".as_bytes(), "n eng!".as_bytes())
        ) as f32 / 2.0) / 6.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn hamming_distance_criterion_with_input_not_multiple_of_size() {
        let input = Vec::from("some random text!!XX".as_bytes());
        let score = hamming_distance_criterion(&input, 3);

        let expected = 1.0 / (((
            bytes::hamming_distance("som".as_bytes(), "e r".as_bytes()) +
            bytes::hamming_distance("and".as_bytes(), "om ".as_bytes()) +
            bytes::hamming_distance("tex".as_bytes(), "t!!".as_bytes())
        ) as f32 / 3.0) / 3.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn hamming_distance_criterion_with_input_pairs_not_multiple_of_2() {
        let input = Vec::from("some random tex!".as_bytes());
        let score = hamming_distance_criterion(&input, 3);

        let expected = 1.0 / (((
            bytes::hamming_distance("som".as_bytes(), "e r".as_bytes()) +
            bytes::hamming_distance("and".as_bytes(), "om ".as_bytes())
        ) as f32 / 2.0) / 3.0);

        assert_eq!(score, expected)
    }

    #[test]
    fn repeated_xor_decrypted() {
        let plain_text = "this text is encrypted with repeated xor".as_bytes();
        let key = "SeCreT".as_bytes();
        let input = Xor::new(key).encrypt(plain_text);

        let keysize_scorer = move |_: &[u8], keysize| {
            if keysize == key.len() as u32 {
                2.0
            } else {
                1.0 / keysize as f32
            }
        };

        let xor_scorer = |input: &[u8]| {
            input
                .iter()
                .filter(|&&b| "this text is encrypted with repeated xor"
                            .as_bytes()
                            .iter()
                            .any(|&c| c == b))
                .count() as f32
        };

        let (resultkey, decrypted) = RepeatedAttack::new()
            .with_single_byte_attack(SingleByteAttack::new()
                                     .with_criterion(Box::new(xor_scorer)))
            .with_keysize_attack(KeysizeAttack::new()
                                 .with_min_length(1)
                                 .with_max_length(15)
                                 .with_criterion(Box::new(keysize_scorer)))
            .result(&input);

        assert_eq!(Vec::from(key), resultkey);
        assert_eq!(Vec::from(plain_text), decrypted);
    }
}
