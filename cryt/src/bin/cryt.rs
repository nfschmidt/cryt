extern crate cryt;
extern crate clap;
use clap::{App, Arg, SubCommand};
use std::io::{self, Read, Write};

use cryt::criteria;
use cryt::encoding;
use cryt::xor;

fn main() {
    let matches = App::new("cryt")
                          .version("v0.1")
                          .author("Nicolas Schmidt <nfschmidt@gmail.com>")
                          .about("Cryptographic tools")
                          .subcommand(SubCommand::with_name("encode")
                                      .about("Encode input with the specified encoding")
                                      .subcommand(SubCommand::with_name("hex")
                                                  .about("Encode input in hex"))
                                      .subcommand(SubCommand::with_name("base64")
                                                  .about("Encode input in base64")))
                          .subcommand(SubCommand::with_name("decode")
                                      .about("Decode input with the specified encoding")
                                      .subcommand(SubCommand::with_name("hex")
                                                  .about("Decode input in hex"))
                                      .subcommand(SubCommand::with_name("base64")
                                                  .about("Decode input in base64")))
                          .subcommand(SubCommand::with_name("encrypt")
                                      .about("Encrypt input with the specified algorithm")
                                      .subcommand(SubCommand::with_name("xor")
                                                  .about("Encrypt using xor")
                                                  .arg(Arg::with_name("key")
                                                       .short("k")
                                                       .long("key")
                                                       .takes_value(true)
                                                       .required(true)
                                                       .help("xor key to be used"))))
                          .subcommand(SubCommand::with_name("encrypt")
                                      .about("Decrypt input with the specified algorithm")
                                      .subcommand(SubCommand::with_name("xor")
                                                  .about("Decrypt using xor")
                                                  .arg(Arg::with_name("key")
                                                       .short("k")
                                                       .long("key")
                                                       .takes_value(true)
                                                       .required(true)
                                                       .help("xor key to be used"))))
                          .subcommand(SubCommand::with_name("attack")
                                      .about("Attack the specified encryption algorithm to decrypt the input")
                                      .subcommand(SubCommand::with_name("xor")
                                                  .about("Attack xor encrypted input")
                                                  .arg(Arg::with_name("criterion")
                                                       .short("c")
                                                       .long("criterion")
                                                       .takes_value(true)
                                                       .possible_values(&["printable", "text"])
                                                       .help("criterion to be used for scoring the results"))
                                                  .arg(Arg::with_name("detailed")
                                                       .short("d")
                                                       .long("detailed")
                                                       .required(false)
                                                       .help("Print decrypted result, the key and the score for the selected criterion"))
                                                  .subcommand(SubCommand::with_name("keysize")
                                                              .about("Determine the keysize of a repeated xor encryption")
                                                              .arg(Arg::with_name("criterion")
                                                                   .help("Criterion to determine keysize")
                                                                   .short("c")
                                                                   .long("criterion")
                                                                   .takes_value(true)
                                                                   .possible_values(&["hamming-distance"])
                                                                   .required(false))
                                                              .arg(Arg::with_name("min")
                                                                   .help("Minimum keysize to try")
                                                                   .long("min")
                                                                   .takes_value(true)
                                                                   .required(false))
                                                              .arg(Arg::with_name("max")
                                                                   .help("Maximum keysize to try")
                                                                   .long("max")
                                                                   .short("m")
                                                                   .takes_value(true)
                                                                   .required(true)))
                                                  .subcommand(SubCommand::with_name("repeated")
                                                              .about("Attack repeated xor encrypted input")
                                                              .arg(Arg::with_name("keysize-criterion")
                                                                   .help("Criterion to determine keysize")
                                                                   .short("k")
                                                                   .long("keysize-criterion")
                                                                   .takes_value(true)
                                                                   .possible_values(&["hamming-distance"])
                                                                   .required(false))
                                                              .arg(Arg::with_name("criterion")
                                                                   .short("c")
                                                                   .long("criterion")
                                                                   .takes_value(true)
                                                                   .possible_values(&["printable", "text"])
                                                                   .help("criterion to be used for scoring the results"))
                                                              .arg(Arg::with_name("min")
                                                                   .help("Minimum keysize to try")
                                                                   .long("min")
                                                                   .takes_value(true)
                                                                   .required(false))
                                                              .arg(Arg::with_name("max")
                                                                   .help("Maximum keysize to try")
                                                                   .long("max")
                                                                   .short("m")
                                                                   .takes_value(true)
                                                                   .required(true)))))
                          .get_matches();


    if let Some(matches) = matches.subcommand_matches("encode") {
        if let Some(_) = matches.subcommand_matches("base64") {
            run_encode_base64();
        } else if let Some(_) = matches.subcommand_matches("hex") {
            run_encode_hex();
        }
    } else if let Some(matches) = matches.subcommand_matches("decode") {
        if let Some(_) = matches.subcommand_matches("base64") {
            run_decode_base64();
        } else if let Some(_) = matches.subcommand_matches("hex") {
            run_decode_hex();
        }
    } else if let Some(matches) = matches.subcommand_matches("encrypt") {
        if let Some(matches) = matches.subcommand_matches("xor") {
            match matches.value_of("key") {
                Some(k) => {
                    run_encrypt_xor(k);
                }
                None => {
                    println!("Error: No key received!");
                }
            }
        }
    } else if let Some(matches) = matches.subcommand_matches("attack") {
        if let Some(xor_matches) = matches.subcommand_matches("xor") {
            if let Some(keysize_matches) = xor_matches.subcommand_matches("keysize") {
                let criterion = match keysize_matches.value_of("criterion") {
                    Some("hamming-distance") => xor::hamming_distance_criterion,
                    Some(_) => xor::hamming_distance_criterion,
                    None => xor::hamming_distance_criterion
                };

                let min = match keysize_matches.value_of("min") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                let max = match keysize_matches.value_of("max") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                run_attack_xor_keysize(criterion, min, max);
                return;
            } else if let Some(repeated_matches) = xor_matches.subcommand_matches("repeated") {
                let xor_criterion = match repeated_matches.value_of("criterion") {
                    Some("printable") => criteria::printable_bytes,
                    Some("text") => criteria::text_bytes,
                    Some(_) => criteria::printable_bytes,
                    None => criteria::printable_bytes
                };

                let keysize_criterion = match repeated_matches.value_of("keysize-criterion") {
                    Some("hamming-distance") => xor::hamming_distance_criterion,
                    Some(_) => xor::hamming_distance_criterion,
                    None => xor::hamming_distance_criterion
                };

                let min = match repeated_matches.value_of("min") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                let max = match repeated_matches.value_of("max") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                run_attack_xor_repeated(keysize_criterion, min, max, xor_criterion);
                return;
            }

            let criterion = match xor_matches.value_of("criterion") {
                Some("printable") => criteria::printable_bytes,
                Some("text") => criteria::text_bytes,
                Some(_) => criteria::printable_bytes,
                None => criteria::printable_bytes
            };

            if xor_matches.is_present("detailed") {
                run_attack_xor_detailed(criterion);
            } else {
                run_attack_xor(criterion);
            }
        }
    } else {
        run_interpreter();
    }
}

fn run_encode_base64() {
    let result = encoding::base64_encode(io::stdin());
    print!("{}", result);
}

fn run_encode_hex() {
    let result = encoding::hex_encode(io::stdin());
    print!("{}", result);
}

fn run_decode_base64() {
    let mut input = String::new();
    match io::stdin().read_to_string(&mut input) {
        Ok(_) => {
            let result: String = encoding::base64_decode(&input)
                .into_iter()
                .map(|b| b as char)
                .collect();
            print!("{}", result);
        }
        Err(error) => { print!("Error: {}", error); }
    }
}

fn run_decode_hex() {
    let mut input = String::new();
    match io::stdin().read_to_string(&mut input) {
        Ok(_) => {
            let result: String = encoding::hex_decode(&input)
                .into_iter()
                .map(|b| b as char)
                .collect();
            print!("{}", result);
        }
        Err(error) => { println!("Error: {}", error); }
    }
}

fn run_encrypt_xor(key: &str) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let result = xor::repeated_xor(&input, key.as_bytes());
    io::stdout().write(&result).unwrap();
}

fn run_attack_xor(criterion: fn(&Vec<u8>) -> f32) {
    let (_, _, decrypted) = xor::single_byte_decrypted(io::stdin(), criterion);
    let result: String = decrypted
        .into_iter()
        .map(|b| b as char)
        .collect();

    print!("{}", result);
}

fn run_attack_xor_detailed(criterion: fn(&Vec<u8>) -> f32) {
    let (key, score, decrypted) = xor::single_byte_decrypted(io::stdin(), criterion);
    let result: String = decrypted
        .into_iter()
        .map(|b| b as char)
        .collect();

    println!("Key: {}\tScore: {}\tResult: {}", key, score, result);
}

fn run_attack_xor_keysize(criterion: fn(&Vec<u8>, size: u32) -> f32, min: u32, max: u32) {
    let results = xor::repeated_xor_keysize(io::stdin(), min, max, criterion);

    for (size, score) in results {
        print!("Size: {}\tScore: {}", size, score);
    }
}

fn run_attack_xor_repeated(keysize_criterion: fn(&Vec<u8>, size: u32) -> f32, min: u32, max: u32, xor_criterion: fn(&Vec<u8>) -> f32) {
    let (key, decrypted) = xor::decrypted_repeated_xor(io::stdin(), min, max, keysize_criterion, xor_criterion);
    let key_string: String = key
        .into_iter()
        .map(|b| b as char)
        .collect();

    let decrypted_string: String = decrypted
        .into_iter()
        .map(|b| b as char)
        .collect();

    print!("Key: {}\nDecrypted:\n{}", key_string, decrypted_string);
}

fn run_interpreter() {
    println!("Interpreter");
}
