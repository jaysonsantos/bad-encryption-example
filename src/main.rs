extern crate ring;
extern crate rayon;
extern crate image;

use std::fs::File;
use std::str;

use image::{open, Pixel, ImageRgb8, ImageFormat};

use rayon::prelude::*;

use ring::aead;
use ring::pbkdf2;
use ring::rand::SystemRandom;

fn main() {
    let nonces_every: Vec<(u32, &'static str)> = vec![(1, "every pixel"),
                                                      (2, "every 2 pixels"),
                                                      (4, "every 4 pixels"),
                                                      (8, "every 8 pixels"),
                                                      (16, "every 16 pixels"),
                                                      (128, "every 128 pixels"),
                                                      (512, "every 512 pixels"),
                                                      (1024, "every 1K pixels"),
                                                      (1024 * 4, "every 4K pixels"),
                                                      (1024 * 64, "every 64K pixels"),
                                                      (1024 * 100, "every 100K pixels"),
                                                      (1024 * 1024, "one per file")];
    let mut reversed_nonces_every = nonces_every.clone();
    reversed_nonces_every.reverse();

    let img = open("origin_image.jpg").unwrap();


    let salt = b"01234567";
    let password = b"a password";
    let mut key = vec![0u8; 32];

    println!("Deriving key");
    pbkdf2::derive(&pbkdf2::HMAC_SHA256,
                   100_000,
                   &salt[..],
                   &password[..],
                   &mut key);
    let key = key;

    println!("Key: {:?}", key);

    let ad: [u8; 0] = [];

    reversed_nonces_every
        .par_iter()
        .enumerate()
        .for_each(|(idx, &(nonce_every, filename))| {
            let rand = SystemRandom::new();
            let filename = format!("output/{:02}_{}.jpg", idx + 1, filename);
            let mut out_file = File::create(&filename).unwrap();
            println!("Generating: {} and creating a new nonce every {} pixel",
                     &filename,
                     nonce_every);
            let mut nonce = [0; 12];
            let mut i = 0u32;
            let mut img = img.clone();
            let mut imgbuf = img.as_mut_rgb8().unwrap();
            for (_, _, pixel) in imgbuf.enumerate_pixels_mut() {
                if i == 0 {
                    rand.fill(&mut nonce).unwrap();
                }
                let sealing_key = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &key).unwrap();
                let mut channels = pixel.channels_mut();
                let mut in_out: Vec<u8> = vec![];
                in_out.extend_from_slice(channels);
                for i in 0..16 {
                    in_out.push(i);
                }
                aead::seal_in_place(&sealing_key,
                                    &nonce,
                                    &ad,
                                    &mut in_out,
                                    aead::CHACHA20_POLY1305.tag_len())
                        .unwrap();
                for channel_number in 0..channels.len() {
                    channels[channel_number] = in_out[channel_number];
                }
                i += 1;
                if i == nonce_every {
                    i = 0;
                }
            }
            let _ = ImageRgb8(imgbuf.clone())
                .save(&mut out_file, ImageFormat::JPEG)
                .unwrap();
        });
}
