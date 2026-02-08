use core::arch::x86_64::_rdtsc;

#[macro_export]
macro_rules! hash {
    ($s:expr) => {{
        const HASH: u32 = $crate::hash::hash_str($s);
        HASH
    }};
}

#[derive(Debug, Copy, Clone)]
pub struct Rng {
    state: u32,
    salt: u32,
}

impl Rng {
    #[inline(always)]
    pub fn new() -> Self {
        Self::from_seed(unsafe { _rdtsc() as u32 })
    }

    #[inline(always)]
    pub fn from_seed(seed: u32) -> Self {
        Self {
            state: seed,
            salt: 0,
        }
    }

    // pub fn set_salt(&mut self, salt: u32) {
    //     self.salt = hash(&salt.to_ne_bytes());
    // }

    #[inline(always)]
    pub fn pass(&mut self) {
        self.state = self.state.wrapping_mul(0x343FD).wrapping_add(0x269EC3);
    }

    #[inline(always)]
    pub fn gen_byte(&mut self) -> u8 {
        self.pass();
        ((self.state >> 16) & 0xFF) as u8
    }

    #[inline(always)]
    pub fn gen_uuid_from_variant(&mut self, original_uuid: &[u8; 16]) -> [u8; 16] {
        let mut b = self.gen_bytes::<16>();

        // preserve UUID version
        b[6] = (original_uuid[6] & 0b11110000u8) | (b[6] & 0b00001111u8);
        // preserve UUID variant
        b[8] = (original_uuid[8] & 0b11000000u8) | (b[8] & 0b00111111u8);

        b
    }

    #[inline(always)]
    pub fn gen_bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes: [u8; N] = [0u8; N];

        bytes.iter_mut().enumerate().for_each(|(i, b)| {
            // self.set_salt(i as _);
            *b = self.gen_byte();
        });

        bytes
    }
}

#[inline(always)]
#[optimize(size)]
pub const fn hash_str(arg: &str) -> u32 {
    hash(arg.as_bytes())
}

#[inline(always)]
pub const fn hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}

#[macro_use]
macro_rules! hash {
    ($x: literal) => {
        const X: u32 = $crate::hash::hash_str($x);
        X
    };
}
