// SPDX-License-Identifier: CC0-1.0

//! 4-way SSE4.1 SHA256 (for `SHA256d` of 64-byte inputs).

#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::inline_always)]
#![allow(non_snake_case)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_add_epi32, _mm_and_si128, _mm_extract_epi32, _mm_or_si128, _mm_set1_epi32,
    _mm_set_epi32, _mm_shuffle_epi8, _mm_slli_epi32, _mm_srli_epi32, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_and_si128, _mm_extract_epi32, _mm_or_si128, _mm_set1_epi32,
    _mm_set_epi32, _mm_shuffle_epi8, _mm_slli_epi32, _mm_srli_epi32, _mm_xor_si128,
};

// ------- SIMD helpers copied from Core -------
// https://github.com/bitcoin/bitcoin/blob/master/src/crypto/sha256_sse41.cpp

#[inline(always)]
unsafe fn K(x: u32) -> __m128i { _mm_set1_epi32(x as i32) }

#[inline(always)]
unsafe fn Add(x: __m128i, y: __m128i) -> __m128i { _mm_add_epi32(x, y) }

#[inline(always)]
unsafe fn Add3(x: __m128i, y: __m128i, z: __m128i) -> __m128i { Add(Add(x, y), z) }

#[inline(always)]
unsafe fn Add4(x: __m128i, y: __m128i, z: __m128i, w: __m128i) -> __m128i { Add(Add(x, y), Add(z, w)) }

#[inline(always)]
unsafe fn Xor(x: __m128i, y: __m128i) -> __m128i { _mm_xor_si128(x, y) }

#[inline(always)]
unsafe fn Xor3(x: __m128i, y: __m128i, z: __m128i) -> __m128i { Xor(Xor(x, y), z) }

#[inline(always)]
unsafe fn Or(x: __m128i, y: __m128i) -> __m128i { _mm_or_si128(x, y) }

#[inline(always)]
unsafe fn And(x: __m128i, y: __m128i) -> __m128i { _mm_and_si128(x, y) }

#[inline(always)]
unsafe fn ShR<const N: i32>(x: __m128i) -> __m128i { _mm_srli_epi32::<N>(x) }

#[inline(always)]
unsafe fn ShL<const N: i32>(x: __m128i) -> __m128i { _mm_slli_epi32::<N>(x) }

#[inline(always)]
unsafe fn Ch(x: __m128i, y: __m128i, z: __m128i) -> __m128i { Xor(z, And(x, Xor(y, z))) }

#[inline(always)]
unsafe fn Maj(x: __m128i, y: __m128i, z: __m128i) -> __m128i { Or(And(x, y), And(z, Or(x, y))) }

#[inline(always)]
unsafe fn Sigma0(x: __m128i) -> __m128i {
    Xor3(Or(ShR::<2>(x), ShL::<30>(x)), Or(ShR::<13>(x), ShL::<19>(x)), Or(ShR::<22>(x), ShL::<10>(x)))
}

#[inline(always)]
unsafe fn Sigma1(x: __m128i) -> __m128i {
    Xor3(Or(ShR::<6>(x), ShL::<26>(x)), Or(ShR::<11>(x), ShL::<21>(x)), Or(ShR::<25>(x), ShL::<7>(x)))
}

#[inline(always)]
unsafe fn sigma0(x: __m128i) -> __m128i {
    Xor3(Or(ShR::<7>(x), ShL::<25>(x)), Or(ShR::<18>(x), ShL::<14>(x)), ShR::<3>(x))
}

#[inline(always)]
unsafe fn sigma1(x: __m128i) -> __m128i {
    Xor3(Or(ShR::<17>(x), ShL::<15>(x)), Or(ShR::<19>(x), ShL::<13>(x)), ShR::<10>(x))
}

#[inline(always)]
unsafe fn Read4(input: &[[u8; 64]; 4], offset: usize) -> __m128i {
    let ret = _mm_set_epi32(
        i32::from_le_bytes(input[0][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[1][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[2][offset..offset + 4].try_into().unwrap()),
        i32::from_le_bytes(input[3][offset..offset + 4].try_into().unwrap()),
    );
    _mm_shuffle_epi8(ret, _mm_set_epi32(0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203))
}

#[inline(always)]
unsafe fn Write4(output: &mut [[u8; 32]; 4], offset: usize, v: __m128i) {
    let v = _mm_shuffle_epi8(v, _mm_set_epi32(0x0C0D0E0F, 0x08090A0B, 0x04050607, 0x00010203));
    output[0][offset..offset + 4].copy_from_slice(&_mm_extract_epi32::<3>(v).to_le_bytes());
    output[1][offset..offset + 4].copy_from_slice(&_mm_extract_epi32::<2>(v).to_le_bytes());
    output[2][offset..offset + 4].copy_from_slice(&_mm_extract_epi32::<1>(v).to_le_bytes());
    output[3][offset..offset + 4].copy_from_slice(&_mm_extract_epi32::<0>(v).to_le_bytes());
}

/// Computes `SHA256d` of four 64-byte inputs in parallel using SSE4.1
#[target_feature(enable = "sse2,ssse3,sse4.1")]
pub(super) unsafe fn sha256d_64_4way(output: &mut [[u8; 32]; 4], input: &[[u8; 64]; 4]) {
    // ------------------ Transform 1 -------------------
    let mut a = K(0x6a09e667);
    let mut b = K(0xbb67ae85);
    let mut c = K(0x3c6ef372);
    let mut d = K(0xa54ff53a);
    let mut e = K(0x510e527f);
    let mut f = K(0x9b05688c);
    let mut g = K(0x1f83d9ab);
    let mut h = K(0x5be0cd19);

    let (mut w0, mut w1, mut w2, mut w3, mut w4, mut w5, mut w6, mut w7);
    let (mut w8, mut w9, mut w10, mut w11, mut w12, mut w13, mut w14, mut w15);

    // Rounds 0-15: message schedule comes directly from the input

    // Round 0
    w0 = Read4(input, 0);
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x428a2f98), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 1
    w1 = Read4(input, 4);
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x71374491), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 2
    w2 = Read4(input, 8);
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xb5c0fbcf), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 3
    w3 = Read4(input, 12);
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xe9b5dba5), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 4
    w4 = Read4(input, 16);
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x3956c25b), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 5
    w5 = Read4(input, 20);
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x59f111f1), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 6
    w6 = Read4(input, 24);
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x923f82a4), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 7
    w7 = Read4(input, 28);
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0xab1c5ed5), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 8
    w8 = Read4(input, 32);
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0xd807aa98), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 9
    w9 = Read4(input, 36);
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x12835b01), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 10
    w10 = Read4(input, 40);
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x243185be), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 11
    w11 = Read4(input, 44);
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x550c7dc3), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 12
    w12 = Read4(input, 48);
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x72be5d74), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 13
    w13 = Read4(input, 52);
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x80deb1fe), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 14
    w14 = Read4(input, 56);
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x9bdc06a7), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 15
    w15 = Read4(input, 60);
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0xc19bf174), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Rounds 16-63: expanded message schedule

    // Round 16
    w0 = Add4(w0, sigma1(w14), w9, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0xe49b69c1), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 17
    w1 = Add4(w1, sigma1(w15), w10, sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xefbe4786), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 18
    w2 = Add4(w2, sigma1(w0), w11, sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x0fc19dc6), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 19
    w3 = Add4(w3, sigma1(w1), w12, sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x240ca1cc), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 20
    w4 = Add4(w4, sigma1(w2), w13, sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x2de92c6f), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 21
    w5 = Add4(w5, sigma1(w3), w14, sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x4a7484aa), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 22
    w6 = Add4(w6, sigma1(w4), w15, sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x5cb0a9dc), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 23
    w7 = Add4(w7, sigma1(w5), w0, sigma0(w8));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x76f988da), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 24
    w8 = Add4(w8, sigma1(w6), w1, sigma0(w9));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x983e5152), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 25
    w9 = Add4(w9, sigma1(w7), w2, sigma0(w10));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xa831c66d), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 26
    w10 = Add4(w10, sigma1(w8), w3, sigma0(w11));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xb00327c8), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 27
    w11 = Add4(w11, sigma1(w9), w4, sigma0(w12));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xbf597fc7), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 28
    w12 = Add4(w12, sigma1(w10), w5, sigma0(w13));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0xc6e00bf3), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 29
    w13 = Add4(w13, sigma1(w11), w6, sigma0(w14));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xd5a79147), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 30
    w14 = Add4(w14, sigma1(w12), w7, sigma0(w15));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x06ca6351), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 31
    w15 = Add4(w15, sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x14292967), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 32
    w0 = Add4(w0, sigma1(w14), w9, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x27b70a85), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 33
    w1 = Add4(w1, sigma1(w15), w10, sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x2e1b2138), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 34
    w2 = Add4(w2, sigma1(w0), w11, sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x4d2c6dfc), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 35
    w3 = Add4(w3, sigma1(w1), w12, sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x53380d13), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 36
    w4 = Add4(w4, sigma1(w2), w13, sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x650a7354), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 37
    w5 = Add4(w5, sigma1(w3), w14, sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x766a0abb), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 38
    w6 = Add4(w6, sigma1(w4), w15, sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x81c2c92e), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 39
    w7 = Add4(w7, sigma1(w5), w0, sigma0(w8));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x92722c85), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 40
    w8 = Add4(w8, sigma1(w6), w1, sigma0(w9));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0xa2bfe8a1), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 41
    w9 = Add4(w9, sigma1(w7), w2, sigma0(w10));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xa81a664b), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 42
    w10 = Add4(w10, sigma1(w8), w3, sigma0(w11));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xc24b8b70), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 43
    w11 = Add4(w11, sigma1(w9), w4, sigma0(w12));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xc76c51a3), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 44
    w12 = Add4(w12, sigma1(w10), w5, sigma0(w13));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0xd192e819), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 45
    w13 = Add4(w13, sigma1(w11), w6, sigma0(w14));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xd6990624), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 46
    w14 = Add4(w14, sigma1(w12), w7, sigma0(w15));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0xf40e3585), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 47
    w15 = Add4(w15, sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x106aa070), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 48
    w0 = Add4(w0, sigma1(w14), w9, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x19a4c116), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 49
    w1 = Add4(w1, sigma1(w15), w10, sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x1e376c08), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 50
    w2 = Add4(w2, sigma1(w0), w11, sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x2748774c), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 51
    w3 = Add4(w3, sigma1(w1), w12, sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x34b0bcb5), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 52
    w4 = Add4(w4, sigma1(w2), w13, sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x391c0cb3), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 53
    w5 = Add4(w5, sigma1(w3), w14, sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x4ed8aa4a), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 54
    w6 = Add4(w6, sigma1(w4), w15, sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x5b9cca4f), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 55
    w7 = Add4(w7, sigma1(w5), w0, sigma0(w8));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x682e6ff3), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 56
    w8 = Add4(w8, sigma1(w6), w1, sigma0(w9));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x748f82ee), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 57
    w9 = Add4(w9, sigma1(w7), w2, sigma0(w10));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x78a5636f), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 58
    w10 = Add4(w10, sigma1(w8), w3, sigma0(w11));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x84c87814), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 59
    w11 = Add4(w11, sigma1(w9), w4, sigma0(w12));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x8cc70208), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 60
    w12 = Add4(w12, sigma1(w10), w5, sigma0(w13));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x90befffa), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 61
    w13 = Add4(w13, sigma1(w11), w6, sigma0(w14));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xa4506ceb), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 62
    w14 = Add4(w14, sigma1(w12), w7, sigma0(w15));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0xbef9a3f7), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 63
    w15 = Add4(w15, sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0xc67178f2), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Transform 1: Update state
    a = Add(a, K(0x6a09e667));
    b = Add(b, K(0xbb67ae85));
    c = Add(c, K(0x3c6ef372));
    d = Add(d, K(0xa54ff53a));
    e = Add(e, K(0x510e527f));
    f = Add(f, K(0x9b05688c));
    g = Add(g, K(0x1f83d9ab));
    h = Add(h, K(0x5be0cd19));

    // Save state
    let s0 = a;
    let s1 = b;
    let s2 = c;
    let s3 = d;
    let s4 = e;
    let s5 = f;
    let s6 = g;
    let s7 = h;

    // ------------------ Transform 2 -------------------
    // W is fully constant here, so we just use pre-computed K[i] + W[i] constant

    // Round 0
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0xc28a2f98));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 1
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0x71374491));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 2
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0xb5c0fbcf));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 3
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0xe9b5dba5));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 4
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x3956c25b));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 5
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x59f111f1));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 6
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x923f82a4));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 7
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xab1c5ed5));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 8
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0xd807aa98));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 9
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0x12835b01));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 10
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0x243185be));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 11
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x550c7dc3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 12
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x72be5d74));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 13
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x80deb1fe));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 14
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x9bdc06a7));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 15
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xc19bf374));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 16
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0x649b69c1));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 17
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0xf0fe4786));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 18
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0x0fe1edc6));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 19
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x240cf254));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 20
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x4fe9346f));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 21
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x6cc984be));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 22
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x61b9411e));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 23
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0x16f988fa));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 24
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0xf2c65152));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 25
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0xa88e5a6d));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 26
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0xb019fc65));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 27
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0xb9d99ec7));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 28
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x9a1231c3));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 29
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0xe70eeaa0));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 30
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0xfdb1232b));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 31
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xc7353eb0));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 32
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0x3069bad5));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 33
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0xcb976d5f));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 34
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0x5a0f118f));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 35
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0xdc1eeefd));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 36
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x0a35b689));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 37
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0xde0b7a04));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 38
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x58f4ca9d));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 39
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xe15d5b16));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 40
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0x007f3e86));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 41
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0x37088980));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 42
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0xa507ea32));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 43
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x6fab9537));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 44
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x17406110));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 45
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x0d8cd6f1));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 46
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0xcdaa3b6d));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 47
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xc0bbbe37));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 48
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0x83613bda));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 49
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0xdb48a363));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 50
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0x0b02e931));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 51
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x6fd15ca7));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 52
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x521afaca));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 53
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x31338431));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 54
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x6ed41a95));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 55
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0x6d437890));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 56
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0xc39c91f2));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 57
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0x9eccabbd));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 58
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0xb5c9a0e6));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 59
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x532fb63c));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 60
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0xd2c741c6));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 61
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x07237ea3));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 62
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0xa4954b68));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 63
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0x4c191d76));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Transform 2: Update state
    w0 = Add(s0, a);
    w1 = Add(s1, b);
    w2 = Add(s2, c);
    w3 = Add(s3, d);
    w4 = Add(s4, e);
    w5 = Add(s5, f);
    w6 = Add(s6, g);
    w7 = Add(s7, h);

    // ------------------ Transform 3 -------------------
    a = K(0x6a09e667);
    b = K(0xbb67ae85);
    c = K(0x3c6ef372);
    d = K(0xa54ff53a);
    e = K(0x510e527f);
    f = K(0x9b05688c);
    g = K(0x1f83d9ab);
    h = K(0x5be0cd19);

    // Rounds 0-7: feed in the 32 byte message (w0..w7)

    // Round 0
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x428a2f98), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 1
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x71374491), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 2
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xb5c0fbcf), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 3
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xe9b5dba5), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 4
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x3956c25b), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 5
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x59f111f1), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 6
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x923f82a4), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 7
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0xab1c5ed5), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Rounds 8-15: known padding

    // Round 8
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), K(0x5807aa98));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 9
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), K(0x12835b01));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 10
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), K(0x243185be));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 11
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), K(0x550c7dc3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 12
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), K(0x72be5d74));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 13
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), K(0x80deb1fe));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 14
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), K(0x9bdc06a7));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 15
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), K(0xc19bf274));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 16
    w0 = Add(w0, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0xe49b69c1), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 17
    w1 = Add3(w1, K(0x00a00000), sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xefbe4786), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 18
    w2 = Add3(w2, sigma1(w0), sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x0fc19dc6), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 19
    w3 = Add3(w3, sigma1(w1), sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x240ca1cc), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 20
    w4 = Add3(w4, sigma1(w2), sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x2de92c6f), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 21
    w5 = Add3(w5, sigma1(w3), sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x4a7484aa), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 22
    w6 = Add4(w6, sigma1(w4), K(0x00000100), sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x5cb0a9dc), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 23
    w7 = Add4(w7, sigma1(w5), w0, K(0x11002000));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x76f988da), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 24
    w8 = Add3(K(0x80000000), sigma1(w6), w1);
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x983e5152), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 25
    w9 = Add(sigma1(w7), w2);
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xa831c66d), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 26
    w10 = Add(sigma1(w8), w3);
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xb00327c8), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 27
    w11 = Add(sigma1(w9), w4);
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xbf597fc7), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 28
    w12 = Add(sigma1(w10), w5);
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0xc6e00bf3), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 29
    w13 = Add(sigma1(w11), w6);
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xd5a79147), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 30
    w14 = Add3(sigma1(w12), w7, K(0x00400022));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x06ca6351), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 31
    w15 = Add4(K(0x00000100), sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x14292967), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 32
    w0 = Add4(w0, sigma1(w14), w9, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x27b70a85), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 33
    w1 = Add4(w1, sigma1(w15), w10, sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x2e1b2138), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 34
    w2 = Add4(w2, sigma1(w0), w11, sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x4d2c6dfc), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 35
    w3 = Add4(w3, sigma1(w1), w12, sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x53380d13), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 36
    w4 = Add4(w4, sigma1(w2), w13, sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x650a7354), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 37
    w5 = Add4(w5, sigma1(w3), w14, sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x766a0abb), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 38
    w6 = Add4(w6, sigma1(w4), w15, sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x81c2c92e), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 39
    w7 = Add4(w7, sigma1(w5), w0, sigma0(w8));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x92722c85), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 40
    w8 = Add4(w8, sigma1(w6), w1, sigma0(w9));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0xa2bfe8a1), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 41
    w9 = Add4(w9, sigma1(w7), w2, sigma0(w10));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0xa81a664b), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 42
    w10 = Add4(w10, sigma1(w8), w3, sigma0(w11));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0xc24b8b70), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 43
    w11 = Add4(w11, sigma1(w9), w4, sigma0(w12));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0xc76c51a3), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 44
    w12 = Add4(w12, sigma1(w10), w5, sigma0(w13));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0xd192e819), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 45
    w13 = Add4(w13, sigma1(w11), w6, sigma0(w14));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xd6990624), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 46
    w14 = Add4(w14, sigma1(w12), w7, sigma0(w15));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0xf40e3585), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 47
    w15 = Add4(w15, sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x106aa070), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 48
    w0 = Add4(w0, sigma1(w14), w9, sigma0(w1));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x19a4c116), w0));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 49
    w1 = Add4(w1, sigma1(w15), w10, sigma0(w2));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x1e376c08), w1));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 50
    w2 = Add4(w2, sigma1(w0), w11, sigma0(w3));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x2748774c), w2));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 51
    w3 = Add4(w3, sigma1(w1), w12, sigma0(w4));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x34b0bcb5), w3));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 52
    w4 = Add4(w4, sigma1(w2), w13, sigma0(w5));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x391c0cb3), w4));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 53
    w5 = Add4(w5, sigma1(w3), w14, sigma0(w6));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0x4ed8aa4a), w5));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 54
    w6 = Add4(w6, sigma1(w4), w15, sigma0(w7));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0x5b9cca4f), w6));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 55
    w7 = Add4(w7, sigma1(w5), w0, sigma0(w8));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0x682e6ff3), w7));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Round 56
    w8 = Add4(w8, sigma1(w6), w1, sigma0(w9));
    let t1 = Add4(h, Sigma1(e), Ch(e, f, g), Add(K(0x748f82ee), w8));
    let t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);

    // Round 57
    w9 = Add4(w9, sigma1(w7), w2, sigma0(w10));
    let t1 = Add4(g, Sigma1(d), Ch(d, e, f), Add(K(0x78a5636f), w9));
    let t2 = Add(Sigma0(h), Maj(h, a, b));
    c = Add(c, t1);
    g = Add(t1, t2);

    // Round 58
    w10 = Add4(w10, sigma1(w8), w3, sigma0(w11));
    let t1 = Add4(f, Sigma1(c), Ch(c, d, e), Add(K(0x84c87814), w10));
    let t2 = Add(Sigma0(g), Maj(g, h, a));
    b = Add(b, t1);
    f = Add(t1, t2);

    // Round 59
    w11 = Add4(w11, sigma1(w9), w4, sigma0(w12));
    let t1 = Add4(e, Sigma1(b), Ch(b, c, d), Add(K(0x8cc70208), w11));
    let t2 = Add(Sigma0(f), Maj(f, g, h));
    a = Add(a, t1);
    e = Add(t1, t2);

    // Round 60
    w12 = Add4(w12, sigma1(w10), w5, sigma0(w13));
    let t1 = Add4(d, Sigma1(a), Ch(a, b, c), Add(K(0x90befffa), w12));
    let t2 = Add(Sigma0(e), Maj(e, f, g));
    h = Add(h, t1);
    d = Add(t1, t2);

    // Round 61
    w13 = Add4(w13, sigma1(w11), w6, sigma0(w14));
    let t1 = Add4(c, Sigma1(h), Ch(h, a, b), Add(K(0xa4506ceb), w13));
    let t2 = Add(Sigma0(d), Maj(d, e, f));
    g = Add(g, t1);
    c = Add(t1, t2);

    // Round 62
    w14 = Add4(w14, sigma1(w12), w7, sigma0(w15));
    let t1 = Add4(b, Sigma1(g), Ch(g, h, a), Add(K(0xbef9a3f7), w14));
    let t2 = Add(Sigma0(c), Maj(c, d, e));
    f = Add(f, t1);
    b = Add(t1, t2);

    // Round 63
    w15 = Add4(w15, sigma1(w13), w8, sigma0(w0));
    let t1 = Add4(a, Sigma1(f), Ch(f, g, h), Add(K(0xc67178f2), w15));
    let t2 = Add(Sigma0(b), Maj(b, c, d));
    e = Add(e, t1);
    a = Add(t1, t2);

    // Transform 3:  Store result
    Write4(output, 0, Add(a, K(0x6a09e667)));
    Write4(output, 4, Add(b, K(0xbb67ae85)));
    Write4(output, 8, Add(c, K(0x3c6ef372)));
    Write4(output, 12, Add(d, K(0xa54ff53a)));
    Write4(output, 16, Add(e, K(0x510e527f)));
    Write4(output, 20, Add(f, K(0x9b05688c)));
    Write4(output, 24, Add(g, K(0x1f83d9ab)));
    Write4(output, 28, Add(h, K(0x5be0cd19)));
}
