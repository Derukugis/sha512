use sha512::{sha512_into, PaddedMessage};

#[cfg(test)] 
mod tests {
    use super::*;
    
    fn td(b: u8) -> u8 { 
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0,
        }
    }

    fn htb(hex: &str, output: &mut [u8]) {
        let hex_bytes = hex.as_bytes();
        for i in 0..output.len() {
            let hi = hex_bytes[2 * i];
            let lo = hex_bytes[2 * i + 1];
            output[i] = ((td(hi) << 4) | td(lo)) as u8;
        }
    }

    fn sha512(bytes: &[u8]) -> [u8; 64] {
        let pl = PaddedMessage::pad_len(bytes.len());
        let mut pad = vec![0u8; pl];
        sha512_into(bytes, &mut pad)
    }
   
    #[test]
    fn hex_string_to_bytes() {
        let hex = "48656c6c6f"; 
        let mut output = [0u8; 5]; 
        htb(hex, &mut output);
        let expected = b"Hello"; 
        assert_eq!(output, *expected);
    }   

    #[test]
    fn string() {
        let result = sha512("The quick brown fox jumps over the lazy dog".as_bytes());
        let mut expected = [0u8; 64];
        htb("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6", &mut expected);
        assert_eq!(&result[..], &expected[..]); 
    }

    #[test]
    fn long_string() {
        let result = sha512("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut in venenatis arcu, a lobortis turpis. Aliquam auctor sagittis magna, id dignissim turpis ullamcorper nec. Aenean justo risus, rutrum vel faucibus a, ultrices vitae arcu. Aliquam erat volutpat. Nam non ipsum eros. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Vestibulum est leo, eleifend eu efficitur eget, auctor et dui. Proin suscipit mi nec quam tincidunt, eget auctor metus semper. Etiam ut justo enim. Aliquam vel vehicula odio. Integer viverra venenatis pharetra. Nam vestibulum interdum urna vel fringilla. Aliquam eget ex enim. Praesent sagittis rutrum neque, vitae consectetur ante fermentum congue. Cras laoreet risus a orci maximus tempor. Praesent laoreet finibus euismod. Vivamus vel nibh lacus. Mauris commodo dolor sed quam posuere, et posuere lorem cursus. Nullam laoreet lobortis risus, sit amet pretium velit sodales vitae. Praesent et gravida nulla. Fusce id leo nunc. Maecenas consequat metus eu dolor posuere, id sagittis leo semper. Morbi consequat luctus eros eget porta. Quisque mauris sem, convallis porta quam sed, convallis molestie tellus. Nullam porta, felis ac consequat convallis, purus mauris cursus lectus, nec suscipit purus felis vel turpis. Fusce imperdiet velit sit amet libero egestas, eu egestas augue vestibulum. Suspendisse luctus purus in vestibulum blandit. Proin aliquet pulvinar est, quis dignissim massa. Etiam volutpat elit eget tincidunt tempus. Aenean accumsan metus nulla, quis mollis nisl elementum malesuada. In lacinia massa eget metus rhoncus, pulvinar condimentum ligula sagittis. Nullam eu luctus velit, eget condimentum leo. Donec in suscipit sem, in mollis mauris. Quisque eleifend aliquam varius. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Morbi venenatis, turpis in tincidunt fermentum, lorem magna faucibus nulla, non elementum augue lorem at urna. Nulla fringilla leo et tempor rutrum. Donec id sem felis. Nulla accumsan purus a nisl non.".as_bytes());
        let mut expected = [0u8; 64];
        htb("2e88448d7062ba9b1188b40f25d34ab787ad2772cfc2ebe540dba4f67042f8c602d5878133b206d379c0bce50fe6d3197e2b3cf10f24d9cc26dfd73b228e3408", &mut expected);
        assert_eq!(&result[..], &expected[..]); 
    }

    #[test]
    fn empty() {
        let result = sha512("".as_bytes());
        let mut expected = [0u8; 64];
        htb("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", &mut expected);
        assert_eq!(&result[..], &expected[..]); 
    }

    #[test]
    fn integer() {
        let result = sha512(&1_u32.to_be_bytes());
        let mut expected = [0u8; 64];
        htb("57c365278e08f99674dd24f08425b17c71b0511dea3b5ffa474deeb26d64cb993ebda4650583b29cba6307d7f4dbb42ca11b093de2b8ecab16ff52445401facf", &mut expected);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn large_integer() {
        let result = sha512(&u128::MAX.to_be_bytes());
        let mut expected = [0u8; 64];
        htb("f637fb3ae44b3646cfd3371d92b38c00ad342993e55e213e3850e72b7fcbad4de42a93edf0ff476e8c4d4d021c24f7b6e9f5b9945ea7ce37ef7639ff4d8869c6", &mut expected);
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn negative_integer() {
        let result = sha512(&(-1_i32).to_be_bytes());
        let mut expected = [0u8; 64];
        htb("ea71bb243b0b2db729b9eb88e3c55a3f490fbff23457825051224a1fe6e6d3f480590cfa3a4a6b12c622d6ac366feb03cd17004ed004cb3f0d52731626946679", &mut expected);
        assert_eq!(&result[..], &expected[..]);
    }
}
