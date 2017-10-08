extern crate cryt;
extern crate clap;
extern crate regex;

use clap::{App, Arg, SubCommand};
use std::io::{self, Read, Write};
use regex::Regex;

use cryt::criteria::{self, BytesCriterion};
use cryt::encoding;
use cryt::xor::{self, Xor, KeysizeCriterion};

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
                          .subcommand(SubCommand::with_name("decrypt")
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
                                                       //.possible_values(&["printable", "text"])
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
                                                              .arg(Arg::with_name("xor-criterion")
                                                                   .short("x")
                                                                   .long("xor-criterion")
                                                                   .takes_value(true)
                                                                   //.possible_values(&["printable", "text"])
                                                                   .help("criterion to be used for scoring the intermediate block results"))
                                                              .arg(Arg::with_name("criterion")
                                                                   .short("c")
                                                                   .long("criterion")
                                                                   .takes_value(true)
                                                                   //.possible_values(&["printable", "text"])
                                                                   .help("criterion to be used for scoring the results for different keysizes"))
                                                              .arg(Arg::with_name("keysizes-try")
                                                                   .short("t")
                                                                   .long("keysizes-try")
                                                                   .takes_value(true)
                                                                   .required(false)
                                                                   .help("criterion to be used for scoring the results for different keysizes"))
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
    } else if let Some(matches) = matches.subcommand_matches("decrypt") {
        if let Some(matches) = matches.subcommand_matches("xor") {
            match matches.value_of("key") {
                Some(k) => {
                    run_decrypt_xor(k);
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
                    Some("hamming-distance") => Box::new(xor::hamming_distance_criterion),
                    Some(_) => Box::new(xor::hamming_distance_criterion),
                    None => Box::new(xor::hamming_distance_criterion),
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
                let xor_criterion: Box<BytesCriterion> = match repeated_matches.value_of("xor-criterion") {
                    Some("printable") => Box::new(criteria::printable_bytes),
                    Some("text") => Box::new(criteria::text_bytes),
                    Some(value) => {
                        let re = Regex::new(r"byte\((\d{1,3})\)").unwrap();
                        let byte_text = re.captures(value).unwrap().get(1).unwrap().as_str();
                        let byte = byte_text.parse::<u8>().unwrap();

                        if value.contains("byte(") {
                            criteria::make_common_byte(byte)
                        } else {
                            Box::new(criteria::text_bytes)
                        }
                    },
                    None => Box::new(criteria::text_bytes)
                };

                let result_criterion: Box<BytesCriterion> = match xor_matches.value_of("criterion") {
                    Some("printable") => Box::new(criteria::printable_bytes),
                    Some("text") => Box::new(criteria::text_bytes),
                    Some(value) => {
                        let re = Regex::new(r"byte\((\d{1,3})\)").unwrap();
                        let byte_text = re.captures(value).unwrap().get(1).unwrap().as_str();
                        let byte = byte_text.parse::<u8>().unwrap();

                        if value.contains("byte(") {
                            criteria::make_common_byte(byte)
                        } else {
                            Box::new(criteria::text_bytes)
                        }
                    },
                    None => Box::new(criteria::text_bytes),
                };


                let keysize_criterion = match repeated_matches.value_of("keysize-criterion") {
                    Some("hamming-distance") => Box::new(xor::hamming_distance_criterion),
                    Some(_) => Box::new(xor::hamming_distance_criterion),
                    None => Box::new(xor::hamming_distance_criterion),
                };

                let keysize_try = match repeated_matches.value_of("keysizes-try") {
                    Some(v) => v.parse::<usize>().unwrap(),
                    None => 1
                };

                let min = match repeated_matches.value_of("min") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                let max = match repeated_matches.value_of("max") {
                    Some(v) => v.parse::<u32>().unwrap(),
                    None => 1
                };

                run_attack_xor_repeated(keysize_criterion, min, max, keysize_try, xor_criterion, result_criterion);
                return;
            }

            let criterion: Box<BytesCriterion> = match xor_matches.value_of("criterion") {
                Some("printable") => Box::new(criteria::printable_bytes),
                Some("text") => Box::new(criteria::text_bytes),
                Some(value) => {
                    let re = Regex::new(r"byte\((\d{1,3})\)").unwrap();
                    let byte_text = re.captures(value).unwrap().get(1).unwrap().as_str();
                    let byte = byte_text.parse::<u8>().unwrap();

                    if value.contains("byte(") {
                        criteria::make_common_byte(byte)
                    } else {
                        Box::new(criteria::text_bytes)
                    }
                },
                None => Box::new(criteria::printable_bytes)
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
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let result = encoding::base64_encode(&input);
    print!("{}", result);
}

fn run_encode_hex() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let result = encoding::hex_encode(&input);
    print!("{}", result);
}

fn run_decode_base64() {
    let mut input = String::new();
    match io::stdin().read_to_string(&mut input) {
        Ok(_) => {
            let result = encoding::base64_decode(&input);
            io::stdout().write(&result).unwrap();
        }
        Err(error) => { println!("Error: {}", error); }
    }
}

fn run_decode_hex() {
    let mut input = String::new();
    match io::stdin().read_to_string(&mut input) {
        Ok(_) => {
            let result = encoding::hex_decode(&input);
            io::stdout().write(&result).unwrap();
        }
        Err(error) => { println!("Error: {}", error); }
    }
}

fn run_encrypt_xor(key: &str) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let result = Xor::new(key.as_bytes()).encrypt(&input);
    io::stdout().write(&result).unwrap();
}

fn run_decrypt_xor(key: &str) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let result = Xor::new(key.as_bytes()).decrypt(&input);
    io::stdout().write(&result).unwrap();
}

fn run_attack_xor(criterion: Box<BytesCriterion>) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let (_, _, decrypted) = xor::SingleByteAttack::new()
        .with_criterion(criterion)
        .result(&input);

    io::stdout().write(&decrypted).unwrap();
}

fn run_attack_xor_detailed(criterion: Box<BytesCriterion>) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let (key, score, decrypted) = xor::SingleByteAttack::new()
        .with_criterion(criterion)
        .result(&input);

    print!("Key: {}\tScore: {}\tResult: ", key, score);
    io::stdout().write(&decrypted).unwrap();
    println!("");
}

fn run_attack_xor_keysize(criterion: Box<KeysizeCriterion>, min: u32, max: u32) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let results = xor::KeysizeAttack::new()
        .with_min_length(min)
        .with_max_length(max)
        .with_criterion(criterion)
        .result(&input);

    for (size, score) in results {
        println!("Size: {}\tScore: {}", size, score);
    }
}

fn run_attack_xor_repeated(keysize_criterion: Box<KeysizeCriterion>, min: u32, max: u32, keysize_try: usize, xor_criterion: Box<BytesCriterion>, result_criterion: Box<BytesCriterion>) {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let (key, decrypted) = xor::RepeatedAttack::new()
        .with_single_byte_attack(xor::SingleByteAttack::new()
                                 .with_criterion(xor_criterion))
        .with_keysize_attack(xor::KeysizeAttack::new()
                             .with_min_length(min)
                             .with_max_length(max)
                             .with_criterion(keysize_criterion))
        .with_result_criterion(result_criterion)
        .with_keysizes_count(keysize_try)
        .result(&input);

    let mut stdout = io::stdout();
    print!("Key: ");
    stdout.write(&key).unwrap();
    print!("\nDecrypted:\n");
    stdout.write(&decrypted).unwrap();
}

fn run_interpreter() {
    println!("Interpreter");
}
