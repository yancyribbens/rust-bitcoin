// SPDX-License-Identifier: CC0-1.0

//! x86 SHA-NI intrinsics for sha256

#![allow(clippy::cast_ptr_alignment)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
    _mm_shuffle_epi8, _mm_storeu_si128,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi64x,
    _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi32,
    _mm_shuffle_epi8, _mm_storeu_si128,
};

/// Processes a single sha256 block using x86 SHA-NI intrinsics.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub(super) unsafe fn process_block(state: &mut [u32; 8], block: &[u8]) {
    // Code translated and based on from
    // https://github.com/noloader/SHA-Intrinsics/blob/4899efc81d1af159c1fd955936c673139f35aea9/sha256-x86.c

    /* sha256-x86.c - Intel SHA extensions using C intrinsics  */
    /*   Written and place in public domain by Jeffrey Walton  */
    /*   Based on code from Intel, and by Sean Gulley for      */
    /*   the miTLS project.                                    */

    // Variable names are also kept the same as in the original C code for easier comparison.
    let (mut state0, mut state1);
    let (mut msg, mut tmp);

    let (mut msg0, mut msg1, mut msg2, mut msg3);

    let (abef_save, cdgh_save);

    #[allow(non_snake_case)]
    let MASK: __m128i =
        _mm_set_epi64x(0x0c0d_0e0f_0809_0a0bu64 as i64, 0x0405_0607_0001_0203u64 as i64);

    let block_offset = 0;

    // Load initial values
    // CAST SAFETY: loadu_si128 documentation states that mem_addr does not
    // need to be aligned on any particular boundary.
    tmp = _mm_loadu_si128(state.as_ptr().add(0).cast::<__m128i>());
    state1 = _mm_loadu_si128(state.as_ptr().add(4).cast::<__m128i>());

    tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
    state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

    // Process a single block
    {
        // Save current state
        abef_save = state0;
        cdgh_save = state1;

        // Rounds 0-3
        msg = _mm_loadu_si128(block.as_ptr().add(block_offset).cast::<__m128i>());
        msg0 = _mm_shuffle_epi8(msg, MASK);
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0xE9B5DBA5B5C0FBCFu64 as i64, 0x71374491428A2F98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 4-7
        msg1 = _mm_loadu_si128(block.as_ptr().add(block_offset + 16).cast::<__m128i>());
        msg1 = _mm_shuffle_epi8(msg1, MASK);
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0xAB1C5ED5923F82A4u64 as i64, 0x59F111F13956C25Bu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 8-11
        msg2 = _mm_loadu_si128(block.as_ptr().add(block_offset + 32).cast::<__m128i>());
        msg2 = _mm_shuffle_epi8(msg2, MASK);
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0x550C7DC3243185BEu64 as i64, 0x12835B01D807AA98u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 12-15
        msg3 = _mm_loadu_si128(block.as_ptr().add(block_offset + 48).cast::<__m128i>());
        msg3 = _mm_shuffle_epi8(msg3, MASK);
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0xC19BF1749BDC06A7u64 as i64, 0x80DEB1FE72BE5D74u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 16-19
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x240CA1CC0FC19DC6u64 as i64, 0xEFBE4786E49B69C1u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 20-23
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x76F988DA5CB0A9DCu64 as i64, 0x4A7484AA2DE92C6Fu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 24-27
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0xBF597FC7B00327C8u64 as i64, 0xA831C66D983E5152u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 28-31
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0x1429296706CA6351u64 as i64, 0xD5A79147C6E00BF3u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 32-35
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x53380D134D2C6DFCu64 as i64, 0x2E1B213827B70A85u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 36-39
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x92722C8581C2C92Eu64 as i64, 0x766A0ABB650A7354u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg0 = _mm_sha256msg1_epu32(msg0, msg1);

        // Rounds 40-43
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0xC76C51A3C24B8B70u64 as i64, 0xA81A664BA2BFE8A1u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg1 = _mm_sha256msg1_epu32(msg1, msg2);

        // Rounds 44-47
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0x106AA070F40E3585u64 as i64, 0xD6990624D192E819u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg3, msg2, 4);
        msg0 = _mm_add_epi32(msg0, tmp);
        msg0 = _mm_sha256msg2_epu32(msg0, msg3);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg2 = _mm_sha256msg1_epu32(msg2, msg3);

        // Rounds 48-51
        msg = _mm_add_epi32(
            msg0,
            _mm_set_epi64x(0x34B0BCB52748774Cu64 as i64, 0x1E376C0819A4C116u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg0, msg3, 4);
        msg1 = _mm_add_epi32(msg1, tmp);
        msg1 = _mm_sha256msg2_epu32(msg1, msg0);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
        msg3 = _mm_sha256msg1_epu32(msg3, msg0);

        // Rounds 52-55
        msg = _mm_add_epi32(
            msg1,
            _mm_set_epi64x(0x682E6FF35B9CCA4Fu64 as i64, 0x4ED8AA4A391C0CB3u64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg1, msg0, 4);
        msg2 = _mm_add_epi32(msg2, tmp);
        msg2 = _mm_sha256msg2_epu32(msg2, msg1);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 56-59
        msg = _mm_add_epi32(
            msg2,
            _mm_set_epi64x(0x8CC7020884C87814u64 as i64, 0x78A5636F748F82EEu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        tmp = _mm_alignr_epi8(msg2, msg1, 4);
        msg3 = _mm_add_epi32(msg3, tmp);
        msg3 = _mm_sha256msg2_epu32(msg3, msg2);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Rounds 60-63
        msg = _mm_add_epi32(
            msg3,
            _mm_set_epi64x(0xC67178F2BEF9A3F7u64 as i64, 0xA4506CEB90BEFFFAu64 as i64),
        );
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        msg = _mm_shuffle_epi32(msg, 0x0E);
        state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

        // Combine state
        state0 = _mm_add_epi32(state0, abef_save);
        state1 = _mm_add_epi32(state1, cdgh_save);
    }

    tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // ABEF

    // Save state
    // CAST SAFETY: storeu_si128 documentation states that mem_addr does not
    // need to be aligned on any particular boundary.
    _mm_storeu_si128(state.as_mut_ptr().add(0).cast::<__m128i>(), state0);
    _mm_storeu_si128(state.as_mut_ptr().add(4).cast::<__m128i>(), state1);
}

/// Computes `SHA256d` of a single 64-byte input using x86 SHA-NI.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn sha256d_64_x86(output: &mut [u8; 32], input: &[u8; 64]) {
    // SHA256 round constants
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];

    // Precomputed W[i] + K[i] for the 2nd transform (padding block).
    #[rustfmt::skip]
    const MIDS: [u32; 64] = [
        0xc28a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf374,
        0x649b69c1, 0xf0fe4786, 0x0fe1edc6, 0x240cf254,
        0x4fe9346f, 0x6cc984be, 0x61b9411e, 0x16f988fa,
        0xf2c65152, 0xa88e5a6d, 0xb019fc65, 0xb9d99ec7,
        0x9a1231c3, 0xe70eeaa0, 0xfdb1232b, 0xc7353eb0,
        0x3069bad5, 0xcb976d5f, 0x5a0f118f, 0xdc1eeefd,
        0x0a35b689, 0xde0b7a04, 0x58f4ca9d, 0xe15d5b16,
        0x007f3e86, 0x37088980, 0xa507ea32, 0x6fab9537,
        0x17406110, 0x0d8cd6f1, 0xcdaa3b6d, 0xc0bbbe37,
        0x83613bda, 0xdb48a363, 0x0b02e931, 0x6fd15ca7,
        0x521afaca, 0x31338431, 0x6ed41a95, 0x6d437890,
        0xc39c91f2, 0x9eccabbd, 0xb5c9a0e6, 0x532fb63c,
        0xd2c741c6, 0x07237ea3, 0xa4954b68, 0x4c191d76
    ];

    // Precomputed values for Transform 3 rounds 9-16.
    // FINS[0..3]: msg2 + K[8..11]
    // FINS[4..7]: _mm_sha256msg1_epu32(msg2, msg3)
    // FINS[8..11]: msg2 + K[12..15]
    #[rustfmt::skip]
    const FINS: [u32; 12] = [
        0x5807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x80000000, 0x00000000, 0x00000000, 0x00000000,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf274,
    ];

    // Padding processed in the 3rd transform (byteswapped).
    const FINAL: [u32; 8] = [0x80000000, 0, 0, 0, 0, 0, 0, 0x100];

    #[allow(non_snake_case)]
    let MASK: __m128i = _mm_set_epi64x(
        0x0c0d_0e0f_0809_0a0bu64 as i64,
        0x0405_0607_0001_0203u64 as i64,
    );

    // Preshuffled SHA256 initial hash values for x86 SHA-NI.
    let init0: __m128i = _mm_set_epi64x(0x6a09e667bb67ae85u64 as i64, 0x510e527f9b05688cu64 as i64);
    let init1: __m128i = _mm_set_epi64x(0x3c6ef372a54ff53au64 as i64, 0x1f83d9ab5be0cd19u64 as i64);

    let (mut state0, mut state1);
    let (abef_save, cdgh_save);
    let (mut msg, mut tmp);
    let (mut msg0, mut msg1, mut msg2, mut msg3);

    // ------------------ Transform 1 -------------------

    // Load state
    state0 = init0;
    state1 = init1;

    // Rounds 0-3
    msg = _mm_loadu_si128(input.as_ptr().add(0).cast::<__m128i>());
    msg0 = _mm_shuffle_epi8(msg, MASK);
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(0).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    msg = _mm_loadu_si128(input.as_ptr().add(16).cast::<__m128i>());
    msg1 = _mm_shuffle_epi8(msg, MASK);
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(4).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 8-11
    msg = _mm_loadu_si128(input.as_ptr().add(32).cast::<__m128i>());
    msg2 = _mm_shuffle_epi8(msg, MASK);
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(8).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 12-15
    msg = _mm_loadu_si128(input.as_ptr().add(48).cast::<__m128i>());
    msg3 = _mm_shuffle_epi8(msg, MASK);
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(12).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 16-19
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(16).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 20-23
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(20).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 24-27
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(24).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 28-31
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(28).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 32-35
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(32).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 36-39
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(36).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 40-43
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(40).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 44-47
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(44).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 48-51
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(48).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 52-55
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(52).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 56-59
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(56).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 60-63
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(60).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Transform 1: Update state
    state0 = _mm_add_epi32(state0, init0);
    state1 = _mm_add_epi32(state1, init1);

    // ------------------ Transform 2 -------------------

    // Save state
    abef_save = state0;
    cdgh_save = state1;

    // Rounds 0-3
    msg = _mm_loadu_si128(MIDS.as_ptr().add(0).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    msg = _mm_loadu_si128(MIDS.as_ptr().add(4).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 8-11
    msg = _mm_loadu_si128(MIDS.as_ptr().add(8).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 12-15
    msg = _mm_loadu_si128(MIDS.as_ptr().add(12).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 16-19
    msg = _mm_loadu_si128(MIDS.as_ptr().add(16).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 20-23
    msg = _mm_loadu_si128(MIDS.as_ptr().add(20).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 24-27
    msg = _mm_loadu_si128(MIDS.as_ptr().add(24).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 28-31
    msg = _mm_loadu_si128(MIDS.as_ptr().add(28).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 32-35
    msg = _mm_loadu_si128(MIDS.as_ptr().add(32).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 36-39
    msg = _mm_loadu_si128(MIDS.as_ptr().add(36).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 40-43
    msg = _mm_loadu_si128(MIDS.as_ptr().add(40).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 44-47
    msg = _mm_loadu_si128(MIDS.as_ptr().add(44).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 48-51
    msg = _mm_loadu_si128(MIDS.as_ptr().add(48).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 52-55
    msg = _mm_loadu_si128(MIDS.as_ptr().add(52).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 56-59
    msg = _mm_loadu_si128(MIDS.as_ptr().add(56).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 60-63
    msg = _mm_loadu_si128(MIDS.as_ptr().add(60).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Transform 2: Update state
    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);

    // Unshuffle to extract hash
    tmp = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    msg0 = _mm_blend_epi16(tmp, state1, 0xF0);
    msg1 = _mm_alignr_epi8(state1, tmp, 8);

    // ------------------ Transform 3 -------------------

    // Load state
    state0 = init0;
    state1 = init1;

    // Rounds 0-3
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(0).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(4).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 8-11
    msg2 = _mm_loadu_si128(FINS.as_ptr().add(4).cast::<__m128i>());
    msg = _mm_loadu_si128(FINS.as_ptr().add(0).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 12-15
    msg3 = _mm_loadu_si128(FINAL.as_ptr().add(4).cast::<__m128i>());
    msg = _mm_loadu_si128(FINS.as_ptr().add(8).cast::<__m128i>());
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 16-19
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(16).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 20-23
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(20).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 24-27
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(24).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 28-31
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(28).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 32-35
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(32).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 36-39
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(36).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg0 = _mm_sha256msg1_epu32(msg0, msg1);

    // Rounds 40-43
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(40).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg1 = _mm_sha256msg1_epu32(msg1, msg2);

    // Rounds 44-47
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(44).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg3, msg2, 4);
    msg0 = _mm_add_epi32(msg0, tmp);
    msg0 = _mm_sha256msg2_epu32(msg0, msg3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg2 = _mm_sha256msg1_epu32(msg2, msg3);

    // Rounds 48-51
    msg = _mm_add_epi32(msg0, _mm_loadu_si128(K.as_ptr().add(48).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg0, msg3, 4);
    msg1 = _mm_add_epi32(msg1, tmp);
    msg1 = _mm_sha256msg2_epu32(msg1, msg0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    msg3 = _mm_sha256msg1_epu32(msg3, msg0);

    // Rounds 52-55
    msg = _mm_add_epi32(msg1, _mm_loadu_si128(K.as_ptr().add(52).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg1, msg0, 4);
    msg2 = _mm_add_epi32(msg2, tmp);
    msg2 = _mm_sha256msg2_epu32(msg2, msg1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 56-59
    msg = _mm_add_epi32(msg2, _mm_loadu_si128(K.as_ptr().add(56).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(msg2, msg1, 4);
    msg3 = _mm_add_epi32(msg3, tmp);
    msg3 = _mm_sha256msg2_epu32(msg3, msg2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 60-63
    msg = _mm_add_epi32(msg3, _mm_loadu_si128(K.as_ptr().add(60).cast::<__m128i>()));
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);


    // Transform 3: Update state
    state0 = _mm_add_epi32(state0, init0);
    state1 = _mm_add_epi32(state1, init1);

    // Unshuffle
    tmp = _mm_shuffle_epi32(state0, 0x1B);
    state1 = _mm_shuffle_epi32(state1, 0xB1);
    state0 = _mm_blend_epi16(tmp, state1, 0xF0);
    state1 = _mm_alignr_epi8(state1, tmp, 8);

    // Store result (byte-swap to big-endian)
    // CAST SAFETY: storeu_si128 does not require alignment.
    _mm_storeu_si128(output.as_mut_ptr().add(0).cast::<__m128i>(), _mm_shuffle_epi8(state0, MASK));
    _mm_storeu_si128(output.as_mut_ptr().add(16).cast::<__m128i>(), _mm_shuffle_epi8(state1, MASK));
}

