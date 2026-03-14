//https://en.wikipedia.org/wiki/SHA-2

#![no_std]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

//Initialize array of round constants:
// (first 64 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
const k: [u64; 80] = [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817];

pub struct PaddedMessage<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl<'a> PaddedMessage<'a> {
    // total length in bytes: original + 1 (0x80) + padding + 16
    pub fn pad_len(m_len: usize) -> usize {
        ((m_len + 1 + 16 + 127) / 128) * 128
    }

    pub fn new(bytes: &[u8], out: &'a mut [u8]) -> Self {
        let ml = bytes.len();
        let pl = Self::pad_len(ml);

        assert!(out.len() >= pl);

        // zero out padded space
        out[..pl].fill(0);

        // copy original
        out[..ml].copy_from_slice(bytes);

        out[ml] = 0x80;

        // append length section
        let bl = (ml as u128) * 8;
        out[pl - 16..pl].copy_from_slice(&bl.to_be_bytes());

        Self { data: out, len: pl }
    }

    pub fn chunk(&self, i: usize) -> &[u8] {
        &self.data[i * 128..(i + 1) * 128]
    }
}

pub fn sha512_into(bytes: &[u8], pad_buf: &mut [u8]) -> [u8; 64] {
    let m = PaddedMessage::new(bytes, pad_buf);

    // Initialize hash values:
    // (first 64 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    let mut hv: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]; 

    // create 80-entry message schedule array w[0..80] of 64-bit words
    let mut w: [u64; 80] = [0; 80];

    // calculate number of 1024-bit chunks
    let num_chunks = m.len / 128;

    // Process the message in successive 1024-bit chunks
    for i in 0..num_chunks {
        let chunk = m.chunk(i);

        // copy chunk into first 16 words w[0..16] as big-endian u64s
        for i in 0..16 {
            let j = i * 8; // j = each word
            w[i] = u64::from_be_bytes([
                chunk[j],
                chunk[j + 1],
                chunk[j + 2],
                chunk[j + 3],
                chunk[j + 4],
                chunk[j + 5],
                chunk[j + 6],
                chunk[j + 7],
            ]);
        }

        // Extend the first 16 words into the remaining 79 words w[16..80] of the message schedule array
        for i in 16..80 {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);

            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = hv[0];
        let mut b = hv[1];
        let mut c = hv[2];
        let mut d = hv[3];
        let mut e = hv[4];
        let mut f = hv[5];
        let mut g = hv[6];
        let mut h = hv[7];

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

        // add the compressed chunk to current hash values
        let cc = [a, b, c, d, e, f, g, h];
        for i in 0..hv.len() {
            hv[i] = hv[i].wrapping_add(cc[i])
        }
    }

    // Produce the final hash value (big-endian)
    let mut hash = [0u8; 64];
    for i in 0..8 {
        // convert each u64 word to big-endian bytes
        // copy said bytes into correct position in hash
        hash[i * 8..(i + 1) * 8].copy_from_slice(&hv[i].to_be_bytes());
    }
    hash
}


