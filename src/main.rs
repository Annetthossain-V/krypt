

use std::env::args;
use std::process::exit;
use std::path::Path;
use std::ffi::OsStr;
use std::fs;
use std::io::{stdin, stdout, Read, Write};


use colored::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit}, // Import Aead for encrypt/decrypt, OsRng for nonce generation
    ChaCha20Poly1305, // The cipher
    Key,               // The key type
    Nonce,             // The nonce type
};

use rand::{rng, Rng};

#[derive(PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}


fn main() {
    
    let argv: Vec<String> = args().skip(1).collect();

    if argv.len() != 2 {
        println!("{}", "Invalid Arguments".bold().bright_red());
        exit(1);
    }

    let mode: Mode;

    match argv[0].as_str() {
        "-c" => mode = Mode::Encrypt,
        "-d" => mode = Mode::Decrypt,

        _ => {
            println!("{}", "Invalid Mode".bright_red().bold());
            println!("{}", "Usage: krypt <Mode> <Filename>".bright_yellow().bold());
            println!("{}", "Mode Has To Be <-c> or <-d>".bright_yellow().bold());
            exit(2);
        }
    }

    let path = Path::new(argv[1].as_str()).extension().and_then(OsStr::to_str);
    let path = path.unwrap();

    if mode == Mode::Decrypt {
        if path != "ks" {
            println!("{}", "Encrypted File Extention Invalid".bright_red().bold());
            exit(3);
        }
    }

    if mode == Mode::Encrypt {
        if path == "ks" {
            println!("{}", "Cannot Encrypt Already Encrypted File".bright_yellow().bold());
            exit(3);
        }
    }


    print!("{} ", "Enter Password:".bright_cyan().bold());
    stdout().flush().unwrap();
    let mut buffer: String = String::new();
    stdin().read_line(&mut buffer).unwrap();
    buffer = buffer[0..(buffer.len() - 1)].to_string();

    let mut passd: [u8; 32] = [43; 32];
    let mut nonce_byte: [u8; 12] = [1; 12];

    if buffer.len() < 32 {
        println!("{}", "Warning! using a password which is less than 32 charactors will result in a weak encryption".bright_yellow().bold());
        // exit(5);
    }

    let mut index: usize = 0;

    let mut buffer_new: String = buffer.clone();
    let mut len = buffer.len();
    while len < 32 {
        buffer_new.push('@');
        len += 1;
    }
    buffer_new.push_str(&buffer);
    // println!("{buffer_new}");

    loop {
        if index > 31 { break }
        let c: char = buffer_new.chars().nth(index).unwrap();
        passd[index] = c as u8;
        index += 1;
    }

    _get_nonce_cipher_gw_fxxvc_internel_core_299(&mut nonce_byte);


    match mode {
        Mode::Encrypt => _enrypt_cs2039_writefile_cc(&argv[1], &passd, &nonce_byte),
        Mode::Decrypt => _decrypt_cs394_read_create_cc(&argv[1], &passd),
    }

    exit(0);
}


fn _enrypt_cs2039_writefile_cc(filename: &str, passwd: &[u8; 32], nonc: &[u8; 12]) {
    let mut plaintext = Vec::new();
    fs::File::open(filename).unwrap().read_to_end(&mut plaintext).unwrap();

    let mut encrypted_file_name = filename.to_owned();
    encrypted_file_name.push_str(".ks");
    let file = fs::File::create_new(Path::new(&encrypted_file_name));
    match file {
        Ok(_) => {},
        Err(_) => { println!("{}", "Unable To Create File!".bright_red().bold()); exit(4) }
    }
    let mut file: fs::File = file.unwrap();


    let key = Key::from_slice(passwd);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonc);
    
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|_| "Encryption failed").unwrap();

    file.write_all(nonce.as_slice()).unwrap();
    file.write_all(&ciphertext).unwrap();
}

fn _decrypt_cs394_read_create_cc(filename: &str, passwd: &[u8; 32]) {

    let filename_purified: String = filename[0..(filename.len() - 3)].to_string();
    let file = fs::File::create_new(Path::new(&filename_purified));
    match file {
        Ok(_) => {},
        Err(_) => { println!("{}", "Unable To Create File!".bright_red().bold()); exit(4) }
    }
    let mut file: fs::File = file.unwrap();

    let mut file_content: Vec<u8> = Vec::new();

    fs::File::open(filename).unwrap().read_to_end(&mut file_content).unwrap();

    let (nonce_byte, ciphertext) = file_content.split_at(12);
    let nonce = Nonce::from_slice(nonce_byte);

    let key = Key::from_slice(passwd);
    let cipher = ChaCha20Poly1305::new(&key);

    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed! Ciphertext may be corrupt or key is wrong.").unwrap();

    file.write_all(&plaintext).unwrap();    

}

fn _get_nonce_cipher_gw_fxxvc_internel_core_299(nonce: &mut [u8; 12]) {

    let mut index: usize = 0;

    loop {
        if index == 12 { break }

        let mut rng = rng();
        let random: u8 = rng.random_range(0..245);

        nonce[index] = random;        // add even more randomness
        // random array TODO

        index += 1
    }

}