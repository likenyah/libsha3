/* SPDX-License-Identifier: 0BSD
 *
 * Copyright © 2022 Alex Minghella <a@minghella.net>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * References
 *
 * [1] Federal Information Processing Standards Publication 202,
 *     SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions,
 *     Information Technology Laboratory, National Institute of Standards and
 *     Technology, August 2015, http://dx.doi.org/10.6028/NIST.FIPS.202
 */

#include "sha3.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * rotl64 - Rotate bits in a 64-bit integer left.
 *
 * @x: 64-bit unsigned integer.
 * @n: Number of steps to rotate bits.
 *
 * @return: @x with bits rotated @n steps left.
 */
static inline uint64_t rotl64(uint64_t x, size_t n)
{
	return (x << n) | (x >> (64 - n));
}

/*
 * GCC, Clang, and ICC manage to transform these into byteswap instructions on
 * instruction sets that have them.
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint32_t bswap32(uint32_t x)
{
	return x >> 24 | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | x << 24;
}

static inline uint64_t bswap64(uint64_t x)
{
	return (bswap32(x) + 0ULL) << 32 | bswap32(x >> 32);
}

static inline uint64_t read64le(const uint64_t *p)
{
	return bswap64(*p);
}
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint64_t read64le(const uint64_t *p)
{
	return *p;
}
#else
	#error Unknown endianness.
#endif

/**
 * keccakf_1600 - KECCAK-f[1600] permutation function.
 *
 * @A: Keccak internal state.
 *
 * @return: None.
 *
 * The loop-based version may be of use somewhere, but it seems more likely
 * that it will always perform worse the unrolled version. It's kept here
 * because it might be easier to follow when comparing to the specification as
 * the steps are actually distinct.
 */
static void keccakf_1600(uint64_t A[25])
#if defined(SHA3_KECCAKF_LOOP)
{
	/*
	 * The round constants can be pre-calculated following Algorithms 5 and
	 * 6 from FIPS 202. [1]
	 */
	static const uint64_t RC[24] = {
		0x0000000000000001ULL, 0x0000000000008082ULL,
		0x800000000000808aULL, 0x8000000080008000ULL,
		0x000000000000808bULL, 0x0000000080000001ULL,
		0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008aULL, 0x0000000000000088ULL,
		0x0000000080008009ULL, 0x000000008000000aULL,
		0x000000008000808bULL, 0x800000000000008bULL,
		0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL,
		0x000000000000800aULL, 0x800000008000000aULL,
		0x8000000080008081ULL, 0x8000000000008080ULL,
		0x0000000080000001ULL, 0x8000000080008008ULL
	};

	/*
	 * The ρ offsets come from Table 2 of FIPS 202 [1]. Each offset is
	 * reduced modulo the lane width before a rotation is applied, so we
	 * pre-calculate the "real" offsets because our lane width is always 64
	 * bits.
	 *
	 *         x=3 x=4 x=0 x=1 x=2
	 *     y=2 153 231   3  10 171
	 *     y=1  55 276  36 300   6
	 *     y=0  28  91   0   1 190
	 *     y=4 120  78 210  66 253
	 *     y=3  21 136 105  45  15
	 *
	 * The reduced offsets here are also reordered to align with the way we
	 * store the Keccak state and the offset for Lane(0, 0) is absent as it
	 * is unmodified in this step.
	 */
	static const uint8_t rho[24] = {
		/*0  1   2   3   4  x / y */
		     1, 62, 28, 27, /*  0 */
		36, 44,  6, 55, 20, /*  1 */
		 3, 10, 43, 25, 39, /*  2 */
		41, 45, 15, 21,  8, /*  3 */
		18,  2, 61, 56, 14  /*  4 */
	};

	/*
	 * The π indices are derived from Figure 5 of FIPS 202 [1]. The diagram
	 * below shows how the lanes in A, labelled with their index in this
	 * implementation's state array, map to the lanes in A′. For example,
	 * Lane(1, 0), or Index(1), in A maps to Lane(1, 1), or Index(6), in
	 * A′.
	 *
	 *         x=3 x=4 x=0 x=1 x=2             x=3 x=4 x=0 x=1 x=2
	 *     y=2  13  14  10  11  12         y=2  12  22   7  17   2
	 *     y=1   8   9   5   6   7    π    y=1  21   6  16   1  11
	 *     y=0   3   4   0   1   2  ---->  y=0   5  15   0  10  20
	 *     y=4  23  24  20  21  22         y=4  19   4  14  24   9
	 *     y=3  18  19  15  16  17         y=3   3  13  23   8  18
	 *                A                               A′
	 *
	 * As before, an index for Lane(0, 0) is absent because it is
	 * unmodified in this step also.
	 */
	static const uint8_t pi[24] = {
		1,  6,  9, 22, 14, 20,
		2, 12, 13, 19, 23, 15,
		4, 24, 21,  8, 16,  5,
		3, 18, 17, 11,  7, 10
	};

	for (uint8_t i_r = 0; i_r < 24; i_r++) {
		/*
		 * θ(A)
		 */
		uint64_t parity[5];
		for (uint8_t i = 0; i < 5; i++)
			parity[i] = A[i] ^ A[i + 5] ^ A[i + 10] ^ A[i + 15] ^ A[i + 20];

		uint64_t tmp[5];
		for (uint8_t i = 0; i < 5; i++) {
			tmp[i] = parity[(i + 4) % 5] ^ rotl64(parity[(i + 1) % 5], 1);

			for (uint8_t j = 0; j < 25; j += 5)
				A[i + j] ^= tmp[i];
		}

		/*
		 * ρ(A)
		 */
		for (uint8_t i = 0; i < 24; i++)
			A[i + 1] = rotl64(A[i + 1], rho[i]);

		/*
		 * π(A)
		 *
		 * By temporarily saving a "start" index, we can order reads
		 * from a given index immediately before writes to that index
		 * to rearrange the state array mostly in-place.
		 *
		 * Choosing 1 as the start point, since it's the first lane to
		 * be affected by this step, we rearrange lanes as:
		 *
		 *     +-- [stack] --------------------------------+
		 *     |                                           |
		 *     1 <- 6 <- 9 <- 22 <- ... <- 11 <- 7 <- 10 <-+
		 */
		tmp[0] = A[pi[0]];
		for (uint8_t i = 0; i < 23; i++)
			A[pi[i]] = A[pi[i + 1]];
		A[pi[23]] = tmp[0];

		/*
		 * χ(A)
		 */
		for (uint8_t i = 0; i < 25; i += 5) {
			for (uint8_t j = 0; j < 5; j++)
				tmp[j] = ~A[i + ((j + 1) % 5)] & A[i + ((j + 2) % 5)];

			for (uint8_t j = 0; j < 5; j++)
				A[i + j] ^= tmp[j];
		}

		/*
		 * ι(A, i_r)
		 */
		A[0] ^= RC[i_r];
	}
}
#else
{
	static const uint64_t RC[24] = {
		0x0000000000000001ULL, 0x0000000000008082ULL,
		0x800000000000808aULL, 0x8000000080008000ULL,
		0x000000000000808bULL, 0x0000000080000001ULL,
		0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008aULL, 0x0000000000000088ULL,
		0x0000000080008009ULL, 0x000000008000000aULL,
		0x000000008000808bULL, 0x800000000000008bULL,
		0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL,
		0x000000000000800aULL, 0x800000008000000aULL,
		0x8000000080008081ULL, 0x8000000000008080ULL,
		0x0000000080000001ULL, 0x8000000080008008ULL
	};

	for (size_t i_r = 0; i_r < 24; i_r++) {
		uint64_t parity[5];
		parity[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
		parity[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
		parity[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
		parity[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
		parity[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

		uint64_t tmp[5];
		tmp[0] = parity[4] ^ rotl64(parity[1], 1);
		tmp[1] = parity[0] ^ rotl64(parity[2], 1);
		tmp[2] = parity[1] ^ rotl64(parity[3], 1);
		tmp[3] = parity[2] ^ rotl64(parity[4], 1);
		tmp[4] = parity[3] ^ rotl64(parity[0], 1);

		/* π∘ρ∘θ(A) */
		uint64_t start = A[1];
		A[ 0] ^= tmp[0];
		A[ 1] = rotl64(A[ 6] ^ tmp[1], 44);
		A[ 6] = rotl64(A[ 9] ^ tmp[4], 20);
		A[ 9] = rotl64(A[22] ^ tmp[2], 61);
		A[22] = rotl64(A[14] ^ tmp[4], 39);
		A[14] = rotl64(A[20] ^ tmp[0], 18);
		A[20] = rotl64(A[ 2] ^ tmp[2], 62);
		A[ 2] = rotl64(A[12] ^ tmp[2], 43);
		A[12] = rotl64(A[13] ^ tmp[3], 25);
		A[13] = rotl64(A[19] ^ tmp[4],  8);
		A[19] = rotl64(A[23] ^ tmp[3], 56);
		A[23] = rotl64(A[15] ^ tmp[0], 41);
		A[15] = rotl64(A[ 4] ^ tmp[4], 27);
		A[ 4] = rotl64(A[24] ^ tmp[4], 14);
		A[24] = rotl64(A[21] ^ tmp[1],  2);
		A[21] = rotl64(A[ 8] ^ tmp[3], 55);
		A[ 8] = rotl64(A[16] ^ tmp[1], 45);
		A[16] = rotl64(A[ 5] ^ tmp[0], 36);
		A[ 5] = rotl64(A[ 3] ^ tmp[3], 28);
		A[ 3] = rotl64(A[18] ^ tmp[3], 21);
		A[18] = rotl64(A[17] ^ tmp[2], 15);
		A[17] = rotl64(A[11] ^ tmp[1], 10);
		A[11] = rotl64(A[ 7] ^ tmp[2],  6);
		A[ 7] = rotl64(A[10] ^ tmp[0],  3);
		A[10] = rotl64(start ^ tmp[1],  1);

		/* χ_0(A) */
		tmp[0] = ~A[1] & A[2];
		tmp[1] = ~A[2] & A[3];
		tmp[2] = ~A[3] & A[4];
		tmp[3] = ~A[4] & A[0];
		tmp[4] = ~A[0] & A[1];
		A[0] ^= tmp[0];
		A[1] ^= tmp[1];
		A[2] ^= tmp[2];
		A[3] ^= tmp[3];
		A[4] ^= tmp[4];

		/* χ_1(A) */
		tmp[0] = ~A[6] & A[7];
		tmp[1] = ~A[7] & A[8];
		tmp[2] = ~A[8] & A[9];
		tmp[3] = ~A[9] & A[5];
		tmp[4] = ~A[5] & A[6];
		A[5] ^= tmp[0];
		A[6] ^= tmp[1];
		A[7] ^= tmp[2];
		A[8] ^= tmp[3];
		A[9] ^= tmp[4];

		/* χ_2(A) */
		tmp[0] = ~A[11] & A[12];
		tmp[1] = ~A[12] & A[13];
		tmp[2] = ~A[13] & A[14];
		tmp[3] = ~A[14] & A[10];
		tmp[4] = ~A[10] & A[11];
		A[10] ^= tmp[0];
		A[11] ^= tmp[1];
		A[12] ^= tmp[2];
		A[13] ^= tmp[3];
		A[14] ^= tmp[4];

		/* χ_3(A) */
		tmp[0] = ~A[16] & A[17];
		tmp[1] = ~A[17] & A[18];
		tmp[2] = ~A[18] & A[19];
		tmp[3] = ~A[19] & A[15];
		tmp[4] = ~A[15] & A[16];
		A[15] ^= tmp[0];
		A[16] ^= tmp[1];
		A[17] ^= tmp[2];
		A[18] ^= tmp[3];
		A[19] ^= tmp[4];

		/* χ_4(A) */
		tmp[0] = ~A[21] & A[22];
		tmp[1] = ~A[22] & A[23];
		tmp[2] = ~A[23] & A[24];
		tmp[3] = ~A[24] & A[20];
		tmp[4] = ~A[20] & A[21];
		A[20] ^= tmp[0];
		A[21] ^= tmp[1];
		A[22] ^= tmp[2];
		A[23] ^= tmp[3];
		A[24] ^= tmp[4];

		/* ι(A, i_r) */
		A[0] ^= RC[i_r];
	}
}
#endif

void sha3_init(struct sha3_ctx *ctx, enum sha3_algo algo)
{
	ctx->index = 0;
	ctx->rate = 200 - 2 * algo;
	ctx->size = algo;
	memset(ctx->u8, 0, 200);
}

static void sha3_update_aligned(struct sha3_ctx *ctx, const void *buf, size_t len)
{
	/*
	 * Assuming buf is aligned on an 8-byte boundary and both ctx->index
	 * and len are multiples of 8.
	 */
	const uint64_t *p = buf;
	while (len) {
		ctx->u64[ctx->index / 8] ^= read64le(p++);
		ctx->index += 8;
		len -= 8;

		if (ctx->index == ctx->rate) {
			ctx->index = 0;
			keccakf_1600(ctx->u64);
		}
	};
}

void sha3_update(struct sha3_ctx *ctx, const void *buf, size_t len)
{
	/*
	 * This could probably be sped up by trying to read in blocks of
	 * ctx->rate bytes and letting sha3_final() handle leftovers at the
	 * end.
	 */
	if (!(len & 7) && !(ctx->index & 7) && !((uintptr_t)buf & 7)) {
		sha3_update_aligned(ctx, buf, len);
		return;
	}

	const uint8_t *p = buf;
	while (len--) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		uint8_t i = ctx->index++;
		ctx->u8[(i / 8) + (7 - i % 8)] ^= *p++;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		ctx->u8[ctx->index++] ^= *p++;
#endif

		if (ctx->index == ctx->rate) {
			ctx->index = 0;
			keccakf_1600(ctx->u64);
		}
	}
}

void sha3_final(struct sha3_ctx *ctx, void *md)
{
	/*
	 * The SHA-3 functions are defined in terms of the KECCAK[c] sponge
	 * function as follows:
	 *
	 * 	SHA3-n(M) = KECCAK[2n](M || 01, n)
	 *
	 * Within KECCAK[c], the augmented message M || 01 is padded to a
	 * multiple of r bits, where r is the padding rate. (ie. ctx->rate * 8)
	 *
	 * To achieve this here, we add in the 2-bit SHA-3 identifier string at
	 * the current input position and set the final (ie. most-significant)
	 * bit of the initial ctx->rate bytes in the state.
	 *
	 * We can skip the intervening padding bytes because the use of the
	 * pad10*1 padding rule means they're all zero and therefore do not
	 * modify the state.
	 *
	 * Essentially, the final input block looks like
	 *
	 * 	0                                       i      r
	 * 	<random garbage the we previously read> 0110..01
	 *
	 * where r is the padding rate and i is the least-significant bit of
	 * the byte at the current input position.
	 */
	ctx->u8[ctx->index] ^= 0x06;    /* 0b00000110 */
	ctx->u8[ctx->rate - 1] ^= 0x80; /* 0b10000000 */

	/*
	 * We have now completed our final block of input, so apply the
	 * permutation function once more.
	 */
	keccakf_1600(ctx->u64);

	memcpy(md, ctx->u8, ctx->size);
	memset(ctx->u8, 0, 200);
}
