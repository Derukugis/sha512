#![no_std]

//https://en.wikipedia.org/wiki/SHA-2

/*
the message is broken into 1024-bit chunks,
the initial hash values and round constants are extended to 64 bits,
there are 80 rounds instead of 64,
the message schedule array w has 80 64-bit words instead of 64 32-bit words,
to extend the message schedule array w, the loop is from 16 to 79 instead of from 16 to 63,
the round constants are based on the first 80 primes 2..409,
the word size used for calculations is 64 bits long,
the appended length of the message (before pre-processing), in bits, is a 128-bit big-endian integer, and
the shift and rotate amounts used are different.
*/

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//Initialize array of round constants:
// (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
const k: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

pub struct PaddedMessage {
    data: [u8; 128],
    len: usize,
}

impl PaddedMessage {
// constructor
    pub fn new(bytes: &[u8]) -> Self {
        let msg_len = bytes.len();

        // total length in bytes: original + 1 (0x80) + padding + 16 (length)  
        let total_len = ((msg_len + 1 + 16 + 127) / 128) * 128;

        let mut m = Self {
            data: [0u8; 128],
            len: total_len,
        };

        // copy original data
        m.data[..msg_len].copy_from_slice(bytes);

        // append 0x80
        m.data[msg_len] = 0x80;

        // calculate padding
        let bit_len = (msg_len as u128) * 8;

        // append length in bits as 128-bit big-endian integer at the end
        m.data[total_len - 16..total_len].copy_from_slice(&bit_len.to_be_bytes());

        m
    }

    // get a chunk as slice
    pub fn chunk(&self, i: usize) -> &[u8] {
        &self.data[i*128..(i+1)*128]
    }
}

pub fn sha512(bytes: &[u8]) -> [u8; 64]{
    let m = PaddedMessage::new(bytes);

    // Initialize hash values:
    // (first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    let mut h0: u64 = 0x6a09e667f3bcc908;
    let mut h1: u64 = 0xbb67ae8584caa73b;
    let mut h2: u64 = 0x3c6ef372fe94f82b;
    let mut h3: u64 = 0xa54ff53a5f1d36f1;
    let mut h4: u64 = 0x510e527fade682d1;
    let mut h5: u64 = 0x9b05688c2b3e6c1f;
    let mut h6: u64 = 0x1f83d9abfb41bd6b;
    let mut h7: u64 = 0x5be0cd19137e2179;

    // create a 80-entry message schedule array w[0..80] of 64-bit words
    let mut w: [u64; 80] = [0; 80];

    // calculate the number of 1024-bit chunks
    let num_chunks = m.len / 128;

    // Process the message in successive 1024-bit chunks
    for i in 0..num_chunks {        
        let chunk = m.chunk(i);
        // copy chunk into first 16 words w[0..16] as big-endian u64s
        for i in 0..16 {
            let j = i * 8; // j = one word (8 bytes)
            w[i] = u64::from_be_bytes([
                chunk[j],
                chunk[j + 1],
                chunk[j + 2],
                chunk[j + 3],
                chunk[j + 4],
                chunk[j + 5],
                chunk[j + 6],
                chunk[j + 7]
            ]);
        }

        // Extend the first 16 words into the remaining 79 words w[16..80] of the message schedule array
        for i in 16..80 {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            
            w[i] = w[i-16]
                .wrapping_add(s0)
                .wrapping_add(w[i-7])
                .wrapping_add(s1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;
        let mut f = h5;
        let mut g = h6;
        let mut h = h7;

        // Compression function main loop
        for i in 0..80 {
            /*
            S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            ch := (e and f) xor ((not e) and g)
            temp1 := h + S1 + ch + k[i] + w[i]
            S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            maj := (a and b) xor (a and c) xor (b and c)
            temp2 := S0 + maj
            */
            let S1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(S1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let S0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let mj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = S0.wrapping_add(mj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // add the compressed chunk to the current hash value
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
        h5 = h5.wrapping_add(f);
        h6 = h6.wrapping_add(g);
        h7 = h7.wrapping_add(h);
    }

    // Produce the final hash value (big-endian)
    let mut hash = [0u8; 64];
    hash[..8].copy_from_slice(&h0.to_be_bytes());
    hash[8..16].copy_from_slice(&h1.to_be_bytes());
    hash[16..24].copy_from_slice(&h2.to_be_bytes());
    hash[24..32].copy_from_slice(&h3.to_be_bytes());
    hash[32..40].copy_from_slice(&h4.to_be_bytes());
    hash[40..48].copy_from_slice(&h5.to_be_bytes());
    hash[48..56].copy_from_slice(&h6.to_be_bytes());
    hash[56..64].copy_from_slice(&h7.to_be_bytes());
    hash
}



#[cfg(test)] 
mod tests {
    use super::*;

    fn to_digit(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        }
    }

    fn hex_str_to_bytes(hex: &str, output: &mut [u8]) {
        let hex_bytes = hex.as_bytes();
        for i in 0..output.len() {
            let hi = hex_bytes[2 * i];
            let lo = hex_bytes[2 * i + 1];
            output[i] = ((to_digit(hi) << 4) | to_digit(lo)) as u8;
        }
    }


    #[test]
    fn string() {
        let result = sha512("The quick brown fox jumps over the lazy dog".as_bytes());
        let mut expected = [0u8; 64];
        hex_str_to_bytes("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", &mut expected);
        assert_eq!(&result[..], &expected[..]); 
    }
    #[test]
    fn empty() {
        let result = sha512("".as_bytes());
        let mut expected = [0u8; 64];
        hex_str_to_bytes("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", &mut expected);
        assert_eq!(&result[..], &expected[..]); 
    }
    #[test]
    fn integer() {
        let result = sha512(&1_i32.to_be_bytes());
        let mut expected = [0u8; 64];
        hex_str_to_bytes(
            "57c365278e08f99674dd24f08425b17c71b0511dea3b5ffa474deeb26d64cb993ebda4650583b29cba6307d7f4dbb42ca11b093de2b8ecab16ff52445401facf",
            &mut expected,
        );
        assert_eq!(&result[..], &expected[..]);
    }
    #[test]
    fn sha512_speed_test() {
        let data = b"hello";
        let iterations = 1000000;

        for _ in 0..iterations {
            let _ = sha512(data);
        }

        // keep the test passing
        assert!(true);
    }
    
    
    
}
