//! Copyright thomasgruebl 2025
//! License: GNU GPLv3
//! This module contains functions for preparing the exfiltration payload.

use std::fs;

use rand::prelude::*;

use std::io::ErrorKind;
use std::os::unix::fs::FileExt;

use openssl::symm::{Cipher, decrypt, encrypt};

use crate::cli::Cli;
use crate::error::CustomError;

pub fn get_random_packetlength_sample(packet_lengths: &Vec<u16>) -> &u16 {
    let packet_length_sample = packet_lengths.choose(&mut rand::thread_rng()).unwrap();
    //dbg!("Packet length sample: {}", packet_length_sample);

    packet_length_sample
}

pub fn get_random_timedelta_sample(time_deltas: &Vec<f64>) -> &f64 {
    let time_delta_sample = time_deltas.choose(&mut rand::thread_rng()).unwrap();
    time_delta_sample
}

pub fn read_next_n_bytes(n: usize, pos: &mut u64, cli: &Cli) -> Vec<u8> {
    let mut buffer: Vec<u8> = vec![0; n];

    let path: &str = &cli.target;
    let f: fs::File = fs::File::open(path).expect(&CustomError::IOError.to_string());
    let f_len: u64 = f.metadata().unwrap().len();

    assert_eq!(n, buffer.len());
    let f_read_result;
    if f_len < n.try_into().unwrap() {
        buffer.resize(f_len as usize, 0);
    }

    f_read_result = f.read_exact_at(&mut buffer, *pos);
    *pos += n as u64;

    let _f_read = match f_read_result {
        Ok(file) => file,
        Err(error) => match error.kind() {
            ErrorKind::UnexpectedEof => {
                *pos = 0; // reset pos to zero
            }
            other_error => {
                panic!("Could not read bytes from file: {:?}", other_error);
            }
        },
    };

    //dbg!("Buffer: {:?}", buffer);

    buffer
}

// optional: encrypt payload with PSK stored in program
// note: not used for secrecy but to generate entropy
// advantages -> higher entropy of payload text -> resembles real encrypted QUIC payload entropy
pub fn encrypt_payload(payload: &Vec<u8>) -> Vec<u8> {
    let key: &[u8; 32] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
    let iv: &[u8; 16] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07";

    // Using AES-256 counter mode instead of CBC to map plaintext onto same length ciphertext
    let cipher: Cipher = Cipher::aes_256_ctr();
    let ciphertext: Vec<u8> = encrypt(cipher, key, Some(iv), payload).unwrap();

    //let reconstructed_plain = decrypt(cipher, key, Some(iv), &ciphertext).unwrap();
    //dbg!("Ciphertext: {:?}", ciphertext);
    //dbg!("Original plaintext: {:?}", payload);
    //dbg!("Reconstruced plaintext: {:?}", reconstructed_plain);

    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encryption() {
        let payload: Vec<u8> = b"abcXYZ!".to_vec();
        let ciphertext: Vec<u8> = encrypt_payload(&payload);
        assert_ne!(ciphertext.len(), 0);
        assert_eq!(ciphertext, [45, 250, 28, 29, 42, 15, 178]);
    }
}
