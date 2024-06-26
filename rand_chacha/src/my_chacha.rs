use core::fmt::Debug;

mod const_calculator {
    const BLOCK: usize = 16;
    const BLOCK64: u64 = BLOCK as u64;
    const LOG2_BUFBLOCKS: u64 = 2;
    const BUFBLOCKS: u64 = 1 << LOG2_BUFBLOCKS;
    pub(super) const BUFSZ64: u64 = BLOCK64 * BUFBLOCKS;
}
const BUFSZ: usize = const_calculator::BUFSZ64 as usize;

pub struct ChaCha20Core {
    pub state: ChaCha,
}

pub struct ChaCha20Rng {
    pub rng: BlockRng,
}

impl ChaCha20Rng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let core = ChaCha20Core::from_seed(seed);
        Self {
            rng: BlockRng::new(core),
        }
    }

    // impl RngCore for ChaCha20Rng {
    pub fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    pub fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    pub fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.rng.fill_bytes(bytes)
    }
}

pub struct BlockRng {
    results: [u32; 64],
    index: usize,
    /// The *core* part of the RNG, implementing the `generate` function.
    pub core: ChaCha20Core,
}

impl BlockRng {
    pub fn new(core: ChaCha20Core) -> BlockRng {
        let results_empty = [u32::default(); 64];
        BlockRng {
            core,
            index: results_empty.as_ref().len(),
            results: results_empty,
        }
    }

    fn next_u32(&mut self) -> u32 {
        if self.index >= self.results.as_ref().len() {
            self.generate_and_set(0);
        }

        let value = self.results.as_ref()[self.index];
        self.index += 1;
        value
    }

    fn next_u64(&mut self) -> u64 {
        let read_u64 = |results: &[u32], index| {
            let data = &results[index..=index + 1];
            u64::from(data[1]) << 32 | u64::from(data[0])
        };

        let len = self.results.as_ref().len();

        let index = self.index;
        if index < len - 1 {
            self.index += 2;
            // Read an u64 from the current index
            read_u64(self.results.as_ref(), index)
        } else if index >= len {
            self.generate_and_set(2);
            read_u64(self.results.as_ref(), 0)
        } else {
            let x = u64::from(self.results.as_ref()[len - 1]);
            self.generate_and_set(1);
            let y = u64::from(self.results.as_ref()[0]);
            (y << 32) | x
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut read_len = 0;
        while read_len < dest.len() {
            if self.index >= self.results.as_ref().len() {
                self.generate_and_set(0);
            }
            let (consumed_u32, filled_u8) = fill_via_u32_chunks(
                &mut self.results.as_mut()[self.index..],
                &mut dest[read_len..],
            );

            self.index += consumed_u32;
            read_len += filled_u8;
        }
    }

    pub fn generate_and_set(&mut self, index: usize) {
        assert!(index < self.results.as_ref().len());
        self.core.generate(&mut self.results);
        self.index = index;
    }
}

pub fn fill_via_u32_chunks(src: &mut [u32], dest: &mut [u8]) -> (usize, usize) {
    let size = core::mem::size_of::<u32>();
    let byte_len = core::cmp::min(core::mem::size_of_val(src), dest.len());
    let num_chunks = (byte_len + size - 1) / size;

    // Byte-swap for portability of results. This must happen before copying
    // since the size of dest is not guaranteed to be a multiple of T or to be
    // sufficiently aligned.
    if cfg!(target_endian = "big") {
        for x in &mut src[..num_chunks] {
            *x = x.to_le();
        }
    }

    dest[..byte_len].copy_from_slice(&as_bytes(&src[..num_chunks])[..byte_len]);

    (num_chunks, byte_len)
}

/// zerocopy AsBytes
fn as_bytes(item: &[u32]) -> &[u8] {
    // Note that this method does not have a `Self: Sized` bound;
    // `size_of_val` works for unsized values too.
    let len = core::mem::size_of_val(item);
    let slf: *const [u32] = item;

    unsafe { core::slice::from_raw_parts(slf.cast::<u8>(), len) }
}

#[derive(Clone)]
pub struct ChaCha {
    pub(crate) b: [u32; 4],
    pub(crate) c: [u32; 4],
    pub(crate) d: [u32; 4],
}
impl ChaCha {
    pub fn new(key: &[u8; 32], nonce: &[u8]) -> Self {
        let ctr_nonce = [
            0,
            if nonce.len() == 12 {
                read_u32le(&nonce[0..4])
            } else {
                0
            },
            read_u32le(&nonce[nonce.len() - 8..nonce.len() - 4]),
            read_u32le(&nonce[nonce.len() - 4..]),
        ];
        let key0 = read_le(&key[..16]);
        let key1 = read_le(&key[16..]);
        ChaCha {
            b: key0,
            c: key1,
            d: ctr_nonce,
        }
    }

    pub fn refill4(&mut self, drounds: u32, out: &mut [u32; BUFSZ]) {
        refill_wide_impl(self, drounds, out)
    }
}

fn read_u32le(xs: &[u8]) -> u32 {
    assert_eq!(xs.len(), 4);
    u32::from(xs[0]) | (u32::from(xs[1]) << 8) | (u32::from(xs[2]) << 16) | (u32::from(xs[3]) << 24)
}

fn refill_wide_impl(state: &mut ChaCha, drounds: u32, out: &mut [u32; BUFSZ]) {
    let k = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let b = state.b;
    let c = state.c;
    let mut x = State {
        a: [k, k, k, k],
        b: [b, b, b, b],
        c: [c, c, c, c],
        d: d0123(state.d),
    };
    for _ in 0..drounds {
        x = undiagonalize(round(diagonalize(round(x))));
    }
    let sb = state.b;
    let sc = state.c;
    let sd = d0123(state.d);
    let results = transpose4(
        nested_map_wrapping_add(x.a, [k, k, k, k]),
        nested_map_wrapping_add(x.b, [sb, sb, sb, sb]),
        nested_map_wrapping_add(x.c, [sc, sc, sc, sc]),
        nested_map_wrapping_add(x.d, sd),
    );
    out[0..16].copy_from_slice(&concat(results.0));
    out[16..32].copy_from_slice(&concat(results.1));
    out[32..48].copy_from_slice(&concat(results.2));
    out[48..64].copy_from_slice(&concat(results.3));
    state.d = add_pos(sd[0], 4).into();
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub(crate) a: [[u32; 4]; 4],
    pub(crate) b: [[u32; 4]; 4],
    pub(crate) c: [[u32; 4]; 4],
    pub(crate) d: [[u32; 4]; 4],
}

#[inline(always)]
pub(crate) fn round(mut x: State) -> State {
    x.a = nested_map_wrapping_add(x.a, x.b);
    x.d = map(bitxor_x4(x.d, x.a), |y| rotate_each_word_right(y, 16));
    x.c = nested_map_wrapping_add(x.c, x.d);
    x.b = map(bitxor_x4(x.b, x.c), |y| rotate_each_word_right(y, 20));
    x.a = nested_map_wrapping_add(x.a, x.b);
    x.d = map(bitxor_x4(x.d, x.a), |y| rotate_each_word_right(y, 24));
    x.c = nested_map_wrapping_add(x.c, x.d);
    x.b = map(bitxor_x4(x.b, x.c), |y| rotate_each_word_right(y, 25));
    x
}

fn rotate_each_word_right(array: [u32; 4], n: u32) -> [u32; 4] {
    map(array, |x| x.rotate_right(n))
}

#[inline(always)]
pub(crate) fn diagonalize(mut x: State) -> State {
    x.b = map(x.b, shuffle_lane_words3012);
    x.c = map(x.c, shuffle_lane_words2301);
    x.d = map(x.d, shuffle_lane_words1230);
    x
}
#[inline(always)]
pub(crate) fn undiagonalize(mut x: State) -> State {
    x.b = map(x.b, shuffle_lane_words1230);
    x.c = map(x.c, shuffle_lane_words2301);
    x.d = map(x.d, shuffle_lane_words3012);
    x
}

// This implementation is platform-independent.
#[inline(always)]
#[cfg(target_endian = "big")]
fn add_pos<Mach: Machine>(_m: Mach, d0: Mach::u32x4, i: u64) -> Mach::u32x4 {
    let pos0 = ((d0.extract(1) as u64) << 32) | d0.extract(0) as u64;
    let pos = pos0.wrapping_add(i);
    d0.insert((pos >> 32) as u32, 1).insert(pos as u32, 0)
}
#[inline(always)]
#[cfg(target_endian = "big")]
fn d0123<Mach: Machine>(m: Mach, d: vec128) -> Mach::u32x4x4 {
    let d0: Mach::u32x4 = m.unpack(d);
    let mut pos = ((d0.extract(1) as u64) << 32) | d0.extract(0) as u64;
    pos = pos.wrapping_add(1);
    let d1 = d0.insert((pos >> 32) as u32, 1).insert(pos as u32, 0);
    pos = pos.wrapping_add(1);
    let d2 = d0.insert((pos >> 32) as u32, 1).insert(pos as u32, 0);
    pos = pos.wrapping_add(1);
    let d3 = d0.insert((pos >> 32) as u32, 1).insert(pos as u32, 0);
    Mach::u32x4x4::from_lanes([d0, d1, d2, d3])
}

// Pos is packed into the state vectors as a little-endian u64,
// so on LE platforms we can use native vector ops to increment it.
#[inline(always)]
#[cfg(target_endian = "little")]
fn add_pos(d: [u32; 4], i: u64) -> [u32; 4] {
    vaporize(map2(condense(d), [i, 0], u64::wrapping_add))
}

#[inline(always)]
#[cfg(target_endian = "little")]
fn d0123(d: [u32; 4]) -> [[u32; 4]; 4] {
    let condensed = condense(d);
    [
        vaporize(map2(condensed, [0, 0], u64::wrapping_add)),
        vaporize(map2(condensed, [1, 0], u64::wrapping_add)),
        vaporize(map2(condensed, [2, 0], u64::wrapping_add)),
        vaporize(map2(condensed, [3, 0], u64::wrapping_add)),
    ]
}

//////////////////////////////////////

fn read_le(input: &[u8]) -> [u32; 4] {
    assert_eq!(input.len(), 16);
    let x: [u32; 4] =
        unsafe { core::mem::transmute(core::ptr::read(input as *const _ as *const [u8; 16])) };

    map(x, |x| x.to_le())
}

fn nested_map_wrapping_add(a: [[u32; 4]; 4], b: [[u32; 4]; 4]) -> [[u32; 4]; 4] {
    map2(a, b, |ai, bi| map2(ai, bi, u32::wrapping_add))
}

fn bitxor_x4(lhs: [[u32; 4]; 4], rhs: [[u32; 4]; 4]) -> [[u32; 4]; 4] {
    map2(lhs, rhs, |a, b| sublimate(deposit(a) ^ deposit(b)))
}

fn transpose4(
    a: [[u32; 4]; 4],
    b: [[u32; 4]; 4],
    c: [[u32; 4]; 4],
    d: [[u32; 4]; 4],
) -> ([[u32; 4]; 4], [[u32; 4]; 4], [[u32; 4]; 4], [[u32; 4]; 4])
where
    [[u32; 4]; 4]: Sized,
{
    (
        [a[0], b[0], c[0], d[0]],
        [a[1], b[1], c[1], d[1]],
        [a[2], b[2], c[2], d[2]],
        [a[3], b[3], c[3], d[3]],
    )
}

fn shuffle_lane_words2301(item: [u32; 4]) -> [u32; 4] {
    [item[2], item[3], item[0], item[1]]
}

/// NOTE: misnomer
fn shuffle_lane_words1230(item: [u32; 4]) -> [u32; 4] {
    [item[3], item[0], item[1], item[2]]
}

/// NOTE: misnomer
fn shuffle_lane_words3012(item: [u32; 4]) -> [u32; 4] {
    [item[1], item[2], item[3], item[0]]
}

fn concat(x4x4: [[u32; 4]; 4]) -> [u32; 16] {
    let [a, b, c, d] = x4x4;
    [
        a[0], a[1], a[2], a[3], //
        b[0], b[1], b[2], b[3], //
        c[0], c[1], c[2], c[3], //
        d[0], d[1], d[2], d[3], //
    ]
}

fn deposit(gas: [u32; 4]) -> u128 {
    unsafe { vec128 { gas }.solid }
}

fn sublimate(solid: u128) -> [u32; 4] {
    unsafe { vec128 { solid }.gas }
}

fn condense(gas: [u32; 4]) -> [u64; 2] {
    unsafe { vec128 { gas }.liquid }
}

fn vaporize(liquid: [u64; 2]) -> [u32; 4] {
    unsafe { vec128 { liquid }.gas }
}

#[test]
fn thing() {
    let gas = [u32::MAX / 2, u32::MAX / 5, u32::MAX / 7, u32::MAX / 11];
    let liquid = condense(gas);
    let solid = deposit(gas);
    let expected_liquid = [3689348816030400511, 1676976733025356068];
    let expected_solid = 30934760611684291960695475747055206399;
    assert_eq!(expected_liquid, liquid);
    assert_eq!(expected_solid, solid);
    assert_eq!(gas, vaporize(liquid));
    assert_eq!(gas, sublimate(solid));
}

#[repr(C)]
union vec128 {
    solid: u128,
    liquid: [u64; 2],
    gas: [u32; 4],
}

fn map<T, F, const N: usize>(a: [T; N], f: F) -> [T; N]
where
    T: Copy + Debug,
    F: Fn(T) -> T,
{
    a.into_iter().map(f).collect::<Vec<_>>().try_into().unwrap()
}

fn map2<T, F, const N: usize>(a: [T; N], b: [T; N], f: F) -> [T; N]
where
    T: Copy + Debug,
    F: Fn(T, T) -> T,
{
    a.into_iter()
        .zip(b.into_iter())
        .map(|(x, y)| f(x, y))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

const rounds: u32 = 10;
impl ChaCha20Core {
    fn from_seed(seed: [u8; 32]) -> Self {
        ChaCha20Core {
            state: ChaCha::new(&seed, &[0u8; 8]),
        }
    }

    fn generate(&mut self, r: &mut [u32; 64]) {
        self.state.refill4(rounds, r);
    }
}

mod test {
    use rand_core::{RngCore, SeedableRng};

    use crate::my_chacha::{round, State};

    #[test]
    fn hardcoded_fill_bytes_test() {
        // type ChaChaRng = super::super::ChaCha20Rng;
        type ChaChaRng = super::ChaCha20Rng;
        let rng = &mut ChaChaRng::from_seed([0; 32]);
        let mut dest = [0u8; 32];
        let midpoint = [
            118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229, 83, 134, 189, 40, 189, 210,
            25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 139, 119, 13, 199,
        ];
        rng.fill_bytes(&mut dest);
        assert_eq!(midpoint, dest);
    }

    #[test]
    fn dynamic_fill_bytes_test() {
        type Reference = super::super::ChaCha20Rng;
        type Mine = super::ChaCha20Rng;
        let mut ref_seed = [0u8; 32];
        let mut my_seed = [0u8; 32];
        for _ in 0..10 {
            let ref_rng = &mut Reference::from_seed(ref_seed);
            let my_rng = &mut Mine::from_seed(my_seed);
            ref_rng.fill_bytes(&mut ref_seed);
            my_rng.fill_bytes(&mut my_seed);
            assert_eq!(ref_seed, my_seed);
            ref_rng.fill_bytes(&mut ref_seed);
            my_rng.fill_bytes(&mut my_seed);
            assert_eq!(ref_seed, my_seed);
        }
    }

    #[test]
    fn dynamic_next_uint_test() {
        type Reference = super::super::ChaCha20Rng;
        type Mine = super::ChaCha20Rng;
        let mut seed = [0u8; 32];
        let ref_rng = &mut Reference::from_seed(seed);
        ref_rng.fill_bytes(&mut seed);
        let my_rng = &mut Mine::from_seed(seed);
        let ref_rng = &mut Reference::from_seed(seed);
        for _ in 0..1000 {
            assert_eq!(ref_rng.next_u32(), my_rng.next_u32());
            assert_eq!(ref_rng.next_u64(), my_rng.next_u64());
        }
    }

    #[test]
    fn round_works() {
        let start = State {
            a: [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]],
            b: [
                [16, 17, 18, 19],
                [20, 21, 22, 23],
                [24, 25, 26, 27],
                [28, 29, 30, 31],
            ],
            c: [
                [32, 33, 34, 35],
                [36, 37, 38, 39],
                [40, 41, 42, 43],
                [44, 45, 46, 47],
            ],
            d: [
                [48, 49, 50, 51],
                [52, 53, 54, 55],
                [56, 57, 58, 59],
                [60, 61, 62, 63],
            ],
        };
        let expected = State {
            a: [
                [196626, 805502996, 1610809366, 1342373912],
                [3221422106, 4026728476, 2684551198, 2416115744],
                [2147680289, 2952986659, 3758293029, 3489857575],
                [1073938473, 1879244843, 537067565, 268632111],
            ],
            b: [
                [2441679121, 269101448, 2458599458, 319568059],
                [2542629751, 370052078, 2492424772, 353393373],
                [2375079117, 202501204, 2391999998, 252968295],
                [2341779115, 169201202, 2291574680, 152542977],
            ],
            c: [
                [589304352, 539169873, 623253122, 639965299],
                [791419620, 741285141, 690626246, 707338423],
                [454566312, 404431833, 488515082, 505227259],
                [387197292, 337062813, 286403918, 303116095],
            ],
            d: [
                [587207168, 536876080, 620762720, 637540432],
                [788536000, 738204912, 687873696, 704651408],
                [452993408, 402662320, 486548960, 503326672],
                [385886528, 335555440, 285224224, 302001936],
            ],
        };
        assert_eq!(expected, round(start));
    }
}
