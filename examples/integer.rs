use sha512::{sha512_into, PaddedMessage};

fn main() {
    let data: i32 = 123;
    let bytes = data.to_be_bytes();

    let pl = PaddedMessage::pad_len(bytes.len());
    let mut pad = vec![0u8; pl];

    let hash = sha512_into(&bytes, &mut pad);
    println!("{:x?}", hash);
}
