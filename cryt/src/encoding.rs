use std::io::{Read};

const HEX_SYMBOLS: [char; 16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];

const BASE64_SYMBOLS: [char; 64] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

fn byte_to_hex(byte: u8) -> String {
    let upper_nyble_index: usize = (byte >> 4) as usize;
    let lower_nyble_index: usize = (byte & 0x0F) as usize;

    HEX_SYMBOLS[upper_nyble_index].to_string() +
        &HEX_SYMBOLS[lower_nyble_index].to_string()
}

pub fn hex_encode<R: Read>(bytes: R) -> String {
    bytes.bytes()
        .map(|b| b.unwrap())
        .map(byte_to_hex)
        .fold(String::new(), |acc, s| acc + &s)
}

pub fn hex_decode(hex: &String) -> Vec<u8> {
    let mut upper_nyble: u8 = 0;
    let mut result = Vec::new();
    for (i, c) in hex.chars().enumerate() {
        let nyble = HEX_SYMBOLS.iter().position(|&x| x == c)
            .expect("invalid hex symbol") as u8;

        if i % 2 == 1 {
            result.push(upper_nyble << 4 | nyble);
        } else {
            upper_nyble = nyble;
        }
    }
    
    result
}

pub fn base64_encode<R: Read>(bytes: R) -> String {
    let mut result = String::new();
    let mut remaining: u8 = 0;
    let mut b64_symbol_index;
    let mut count = 0;

    for (i, b) in bytes.bytes().map(|b| b.unwrap()).enumerate() {
        count += 1;
        match i % 3 {
            0 => {
                b64_symbol_index = (b >> 2) as usize;
                remaining = (b & 0x03) << 4;
            }
            1 => {
                b64_symbol_index = (remaining | (b >> 4)) as usize;
                remaining = (b & 0x0F) << 2;
            }
            _ => {
                b64_symbol_index = (remaining | (b >> 6)) as usize;
                result.push(BASE64_SYMBOLS[b64_symbol_index]);
                b64_symbol_index = (b & 0x3F) as usize;
            }
        }

        result.push(BASE64_SYMBOLS[b64_symbol_index]);
    }

    if count % 3 == 2 {
        result.push(BASE64_SYMBOLS[remaining as usize]);
        result.push('=');
    } else if count % 3 == 1 {
        result.push(BASE64_SYMBOLS[remaining as usize]);
        result.push('=');
        result.push('=');
    }

    result
}

pub fn base64_decode(b64: &String) -> Vec<u8> {
    let mut result = Vec::new();
    let mut accumulator: u8 = 0;

    for (i, c) in b64.chars().enumerate() {
        if c == '=' {
            break;
        }

        let value = BASE64_SYMBOLS.iter().position(|&x| x == c)
            .expect("invalid base64 symbol") as u8;

        accumulator = match i % 4 {
            0 => value << 2,
            1 => {
                result.push(accumulator | (value >> 4));
                value << 4
            }
            2 => {
                result.push(accumulator | (value >> 2));
                value << 6
            }
            _ => {
                result.push(accumulator | value);
                0
            }
        }
    }

    result
}



#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader};

    #[test]
    fn hex_encoding() {
        let input = [10, 123, 232, 100];
        let reader = BufReader::new(&input[..]);
        assert_eq!(hex_encode(reader), String::from("0a7be864"));
    }

    #[test]
    fn hex_decoding() {
        let input = String::from("0a7be864");
        assert_eq!(hex_decode(&input), [10, 123, 232, 100]);
    }

    #[test]
    fn base64_encoding_without_padding() {
        let input = [116, 101, 115, 116, 52, 33];
        let reader = BufReader::new(&input[..]);
        assert_eq!(base64_encode(reader), String::from("dGVzdDQh"))
    }

    #[test]
    fn base64_encoding_1_padding() {
        let input = [116, 101, 115, 116, 49, 48, 52, 33];
        let reader = BufReader::new(&input[..]);
        assert_eq!(base64_encode(reader), String::from("dGVzdDEwNCE="))
    }

    #[test]
    fn base64_encoding_2_paddings() {
        let input = vec![116, 101, 115, 116, 49, 52, 33];
        let reader = BufReader::new(&input[..]);
        assert_eq!(base64_encode(reader), String::from("dGVzdDE0IQ=="))
    }

    #[test]
    fn base64_decoding_without_padding() {
        let input = String::from("dGVzdDQh");
        assert_eq!(base64_decode(&input), [116, 101, 115, 116, 52, 33]);
    }

    #[test]
    fn base64_decoding_1_padding() {
        let input = String::from("dGVzdDEwNCE=");
        assert_eq!(base64_decode(&input), vec![116, 101, 115, 116, 49, 48, 52, 33]);
    }

    #[test]
    fn base64_decoding_2_paddings() {
        let input = String::from("dGVzdDE0IQ==");
        assert_eq!(base64_decode(&input), vec![116, 101, 115, 116, 49, 52, 33]);
    }
}
