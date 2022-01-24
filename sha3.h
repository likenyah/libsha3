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

#ifndef SHA3_H
#define SHA3_H 1

#include <stddef.h>
#include <stdint.h>

/**
 * enum sha3_algo - SHA-3 algorithm selection constants.
 *
 * @SHA3_224: SHA3-224.
 * @SHA3_256: SHA3-256.
 * @SHA3_384: SHA3-384.
 * @SHA3_512: SHA3-512.
 *
 * NOTE: Do not use these constants to represent the size of a digest, use the
 *       SHA3_*_SIZE constants instead.
 */
enum sha3_algo {
	SHA3_224 = 28,
	SHA3_256 = 32,
	SHA3_384 = 48,
	SHA3_512 = 64,
};

/**
 * enum sha3_size - SHA-3 digest sizes in bytes.
 *
 * @SHA3_224_SIZE: Byte size of a SHA3-224 digest.
 * @SHA3_256_SIZE: Byte size of a SHA3-256 digest.
 * @SHA3_384_SIZE: Byte size of a SHA3-384 digest.
 * @SHA3_512_SIZE: Byte size of a SHA3-512 digest.
 */
enum sha3_size {
	SHA3_224_SIZE = 28,
	SHA3_256_SIZE = 32,
	SHA3_384_SIZE = 48,
	SHA3_512_SIZE = 64
};

/**
 * struct sha3_ctx - SHA-3 context.
 *
 * @index: Byte index in the state that the next input byte will modify.
 * @rate:  Padding rate in bytes. The rate is equal to the difference between
 *         the size of the state and the "capactity" of the algorithm. The
 *         capactity is specified as double the size of digest. SHA3-224, for
 *         example, has a specified capacity of 448 bits, meaning the padding
 *         rate is 1152 bits, or 144 bytes. SHA3-512, similarly, has a padding
 *         rate of 72 bytes.
 * @size:  Digest size in bytes.
 * @u8:    Byte-wise view of the internal state.
 * @u64:   Lane-wise view of the internal state.
 *
 * The lanes of the internal state are labelled as follows:
 *
 *         x=3 x=4 x=0 x=1 x=2
 *     y=2  13  14  10  11  12
 *     y=1   8   9   5   6   7
 *     y=0   3   4   0   1   2
 *     y=4  23  24  20  21  22
 *     y=3  18  19  15  16  17
 *                Lanes
 *
 * In other words, Lane(x, y) in the formal description of the state array maps
 * to Index(x + 5y) in @u64.
 */
struct sha3_ctx {
	uint8_t index;
	uint8_t rate;
	uint8_t size;

	union {
		uint8_t  u8[200];
		uint64_t u64[25];
	};
};

/**
 * sha3_init - Initialise a SHA-3 context structure.
 *
 * @ctx:  Pointer to a SHA-3 context structure.
 * @algo: Size of the final digest in bytes.
 *
 * @return: None.
 */
void sha3_init(struct sha3_ctx *ctx, enum sha3_algo algo);

/**
 * sha3_update - Update a SHA-3 context with input data.
 *
 * @ctx: Pointer to an initialised SHA-3 context structure.
 * @buf: Pointer to input data.
 * @len: Length, in bytes, of the input data.
 *
 * @return: None.
 */
void sha3_update(struct sha3_ctx *ctx, const void *buf, size_t len);

/**
 * sha3_final - Finalise a SHA-3 context and write the digest.
 *
 * @ctx: Pointer to an initialised SHA-3 context structure.
 * @md:  Pointer to the buffer in which the digest will be written. Must be a
 *       valid pointer and may not be NULL.
 *
 * @return: None.
 */
void sha3_final(struct sha3_ctx *ctx, void *md);

#endif /* SHA3_H */
