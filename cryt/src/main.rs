extern crate clap;
use clap::{App, SubCommand};
use std::io::{self, Read};

extern crate encoding;

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

fn run_interpreter() {
    println!("Interpreter");
}
