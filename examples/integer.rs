use sha512::sha512;

fn main() {
    let data: i32 = 123;
    let hash = sha512(&data.to_be_bytes());
    println!("{:x?}", hash);
}
