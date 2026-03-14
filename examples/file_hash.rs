use sha512::{sha512_into, PaddedMessage};
use std::fs::File;
use std::io::{BufReader, Read};

fn main() {
    let file = File::open("examples/file.txt").unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();

    let pl = PaddedMessage::pad_len(buffer.len());
    let mut pad = vec![0u8; pl];

    let hash = sha512_into(&buffer, &mut pad);
    println!("{:x?}", hash);
}
