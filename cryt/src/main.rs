extern crate clap;
use clap::{App, Arg, SubCommand};
use std::io::{self, BufReader, Read};

extern crate criteria;
extern crate encoding;
extern crate xor;

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
                                                       .help("Print decrypted result, the key and the score for the selected criterion"))))
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
            println!("{}", result);
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
    let result: String = xor::repeated_xor(io::stdin(), BufReader::new(key.as_bytes()))
        .into_iter()
        .map(|b| b as char)
        .collect();
    print!("{}", result);
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

fn run_interpreter() {
    println!("Interpreter");
}
