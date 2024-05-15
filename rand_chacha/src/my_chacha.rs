use core::{
    fmt::Debug,
    ops::{Add, AddAssign, BitXor},
};

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
        let key0 = u32x4::read_le(&key[..16]);
        let key1 = u32x4::read_le(&key[16..]);
        ChaCha {
            b: key0.0,
            c: key1.0,
            d: ctr_nonce,
        }
    }

    pub fn refill4(&mut self, drounds: u32, out: &mut [u32; BUFSZ]) {
        unsafe { refill_wide_impl(self, drounds, out) }
    }
}

fn read_u32le(xs: &[u8]) -> u32 {
    assert_eq!(xs.len(), 4);
    u32::from(xs[0]) | (u32::from(xs[1]) << 8) | (u32::from(xs[2]) << 16) | (u32::from(xs[3]) << 24)
}

unsafe fn refill_wide_impl(state: &mut ChaCha, drounds: u32, out: &mut [u32; BUFSZ]) {
    let k = u32x4([0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    let b = u32x4(state.b);
    let c = u32x4(state.c);
    let mut x = State {
        a: x4([k, k, k, k]),
        b: x4([b, b, b, b]),
        c: x4([c, c, c, c]),
        d: d0123(state.d),
    };
    for _ in 0..drounds {
        x = round(x); // 3079110635
        x = diagonalize(x); // 3079110635
        x = round(x); // 3831485001
        x = undiagonalize(x); // 3831485001
        x = x;
    }
    let kk = x4([k, k, k, k]);
    let sb = u32x4(state.b);
    let sb = x4([sb, sb, sb, sb]);
    let sc = u32x4(state.c);
    let sc = x4([sc, sc, sc, sc]);
    let sd = d0123(state.d);
    let results = u32x4x4::transpose4(x.a + kk, x.b + sb, x.c + sc, x.d + sd);
    out[0..16].copy_from_slice(&results.0.to_scalars());
    out[16..32].copy_from_slice(&results.1.to_scalars());
    out[32..48].copy_from_slice(&results.2.to_scalars());
    out[48..64].copy_from_slice(&results.3.to_scalars());
    state.d = add_pos(sd.0[0].0, 4).into();
}

#[derive(Clone)]
pub struct State<V> {
    pub(crate) a: V,
    pub(crate) b: V,
    pub(crate) c: V,
    pub(crate) d: V,
}

#[inline(always)]
pub(crate) fn round(mut x: State<u32x4x4>) -> State<u32x4x4> {
    x.a = x4(wrapping_add_inner_tupled(x.a.0, x.b.0));
    x.d = rotate_each_word_right_x4(x.d ^ x.a, 16);
    x.c = x4(wrapping_add_inner_tupled(x.c.0, x.d.0));
    x.b = rotate_each_word_right_x4(x.b ^ x.c, 20);
    x.a = x4(wrapping_add_inner_tupled(x.a.0, x.b.0));
    x.d = rotate_each_word_right_x4(x.d ^ x.a, 24);
    x.c = x4(wrapping_add_inner_tupled(x.c.0, x.d.0));
    x.b = rotate_each_word_right_x4(x.b ^ x.c, 25);
    x
}

fn rotate_each_word_right_x4(array: u32x4x4, n: u32) -> u32x4x4 {
    x4([
        rotate_each_word_right(array.0[0], n),
        rotate_each_word_right(array.0[1], n),
        rotate_each_word_right(array.0[2], n),
        rotate_each_word_right(array.0[3], n),
    ])
}
fn rotate_each_word_right(array: u32x4, n: u32) -> u32x4 {
    u32x4(map(array.0, |x| x.rotate_right(n)))
}

#[inline(always)]
pub(crate) fn diagonalize(mut x: State<u32x4x4>) -> State<u32x4x4> {
    x.b = x.b.shuffle_lane_words3012();
    x.c = x.c.shuffle_lane_words2301();
    x.d = x.d.shuffle_lane_words1230();
    x
}
#[inline(always)]
pub(crate) fn undiagonalize(mut x: State<u32x4x4>) -> State<u32x4x4> {
    x.b = x.b.shuffle_lane_words1230();
    x.c = x.c.shuffle_lane_words2301();
    x.d = x.d.shuffle_lane_words3012();
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
fn d0123(d: [u32; 4]) -> u32x4x4 {
    let condensed = condense(d);

    x4([
        u32x4(vaporize(map2(condensed, [0, 0], u64::wrapping_add))),
        u32x4(vaporize(map2(condensed, [1, 0], u64::wrapping_add))),
        u32x4(vaporize(map2(condensed, [2, 0], u64::wrapping_add))),
        u32x4(vaporize(map2(condensed, [3, 0], u64::wrapping_add))),
    ])
}

//////////////////////////////////////

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct u32x4([u32; 4]);

impl u32x4 {
    fn read_le(input: &[u8]) -> Self {
        assert_eq!(input.len(), 16);
        let x: u32x4 =
            unsafe { core::mem::transmute(core::ptr::read(input as *const _ as *const [u8; 16])) };

        u32x4(map(x.0, |x| x.to_le()))
    }
}

fn wrapping_add_inner_tupled(a: [u32x4; 4], b: [u32x4; 4]) -> [u32x4; 4] {
    map2(a, b, |ai, bi| u32x4(map2(ai.0, bi.0, u32::wrapping_add)))
}
fn wrapping_add_inner(a: [[u32; 4]; 4], b: [[u32; 4]; 4]) -> [[u32; 4]; 4] {
    map2(a, b, |ai, bi| map2(ai, bi, u32::wrapping_add))
}

impl<W> AddAssign for x4<W>
where
    x4<W>: Copy + Add<Output = x4<W>>,
{
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}
impl BitXor for u32x4 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        u32x4(omap2(self.0, rhs.0, |x, y| x ^ y))
    }
}
impl<W> BitXor for x4<W>
where
    W: Copy + BitXor<Output = W>,
{
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self([
            self.0[0].bitxor(rhs.0[0]),
            self.0[1].bitxor(rhs.0[1]),
            self.0[2].bitxor(rhs.0[2]),
            self.0[3].bitxor(rhs.0[3]),
        ])
    }
}

pub type u32x4x4 = x4<u32x4>;

#[derive(Clone, Copy)]
pub struct x4<W>(pub [W; 4]);

impl Add for x4<u32x4> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        x4(wrapping_add_inner_tupled(self.0, rhs.0))
    }
}

impl<W: Copy> x4<W> {
    #[inline(always)]
    fn transpose4(a: Self, b: Self, c: Self, d: Self) -> (Self, Self, Self, Self)
    where
        Self: Sized,
    {
        (
            x4([a.0[0], b.0[0], c.0[0], d.0[0]]),
            x4([a.0[1], b.0[1], c.0[1], d.0[1]]),
            x4([a.0[2], b.0[2], c.0[2], d.0[2]]),
            x4([a.0[3], b.0[3], c.0[3], d.0[3]]),
        )
    }
}

impl u32x4 {
    #[inline(always)]
    fn shuffle_lane_words2301(self) -> Self {
        self.swap64()
    }
    #[inline(always)]
    fn swap64(self) -> Self {
        u32x4(omap(self.0, |x| (x << 64) | (x >> 64)))
    }
    #[inline(always)]
    fn shuffle_lane_words1230(self) -> Self {
        let x = self.0;
        Self([x[3], x[0], x[1], x[2]])
    }
    #[inline(always)]
    fn shuffle_lane_words3012(self) -> Self {
        let x = self.0;
        Self([x[1], x[2], x[3], x[0]])
    }
}

impl u32x4x4 {
    #[inline(always)]
    fn shuffle_lane_words2301(self) -> Self {
        x4([
            self.0[0].shuffle_lane_words2301(),
            self.0[1].shuffle_lane_words2301(),
            self.0[2].shuffle_lane_words2301(),
            self.0[3].shuffle_lane_words2301(),
        ])
    }
    #[inline(always)]
    fn shuffle_lane_words1230(self) -> Self {
        x4([
            self.0[0].shuffle_lane_words1230(),
            self.0[1].shuffle_lane_words1230(),
            self.0[2].shuffle_lane_words1230(),
            self.0[3].shuffle_lane_words1230(),
        ])
    }
    #[inline(always)]
    fn shuffle_lane_words3012(self) -> Self {
        x4([
            self.0[0].shuffle_lane_words3012(),
            self.0[1].shuffle_lane_words3012(),
            self.0[2].shuffle_lane_words3012(),
            self.0[3].shuffle_lane_words3012(),
        ])
    }
}

impl u32x4x4 {
    fn to_scalars(self) -> [u32; 16] {
        let [a, b, c, d] = self.0;
        let a = a.0;
        let b = b.0;
        let c = c.0;
        let d = d.0;
        [
            a[0], a[1], a[2], a[3], //
            b[0], b[1], b[2], b[3], //
            c[0], c[1], c[2], c[3], //
            d[0], d[1], d[2], d[3], //
        ]
    }
}

fn omap<F>(a: [u32; 4], f: F) -> [u32; 4]
where
    F: Fn(u128) -> u128,
{
    let ao = freeze(condense(a));
    vaporize(melt(f(ao)))
}

fn omap2<F>(a: [u32; 4], b: [u32; 4], f: F) -> [u32; 4]
where
    F: Fn(u128, u128) -> u128,
{
    let ao = freeze(condense(a));
    let bo = freeze(condense(b));
    vaporize(melt(f(ao, bo)))
}

fn freeze(q: [u64; 2]) -> u128 {
    u128::from(q[0]) | (u128::from(q[1]) << 64)
}

fn melt(o: u128) -> [u64; 2] {
    [o as u64, (o >> 64) as u64]
}

fn condense(input: [u32; 4]) -> [u64; 2] {
    unsafe { vec128 { d: input }.q }
}

fn vaporize(input: [u64; 2]) -> [u32; 4] {
    unsafe { vec128 { q: input }.d }
}

#[repr(C)]
union vec128 {
    d: [u32; 4],
    q: [u64; 2],
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
    #[inline]
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
        for _ in 0..10 {
            assert_eq!(ref_rng.next_u32(), my_rng.next_u32());
            assert_eq!(ref_rng.next_u64(), my_rng.next_u64());
        }
    }
}
