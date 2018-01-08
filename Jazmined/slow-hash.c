// Copyright 2018 Waitman Gobble
// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <emmintrin.h>
#include <wmmintrin.h>

#include <intrin.h>

#include "aesb.h"
#include "initializer.h"
#include "int-util.h"
#include "hash-ops.h"
#include "oaes_lib.h"

#define likely(x) (x)
#define unlikely(x) (x)
#define __attribute__(x)

void(*cn_slow_hash_fp)(void *, const void *, size_t, void *);

void cn_slow_hash_f(void * a, const void * b, size_t c, void * d) {
	(*cn_slow_hash_fp)(a, b, c, d);
}

#define restrict

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)	// 128
#define ALIGNED_DATA(x) __declspec(align(x))
#define ALIGNED_DECL(t, x) ALIGNED_DATA(x) t

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)


struct cn_ctx {
	ALIGNED_DECL(uint8_t long_state[MEMORY], 16);
	ALIGNED_DECL(union cn_slow_hash_state state, 16);
	ALIGNED_DECL(uint8_t text[INIT_SIZE_BYTE], 16);
	ALIGNED_DECL(uint64_t a[AES_BLOCK_SIZE >> 3], 16);
	ALIGNED_DECL(uint64_t b[AES_BLOCK_SIZE >> 3], 16);
	ALIGNED_DECL(uint8_t c[AES_BLOCK_SIZE], 16);
	oaes_ctx* aes_ctx;
};

static_assert(sizeof(struct cn_ctx) == SLOW_HASH_CONTEXT_SIZE, "Invalid structure size");

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
	__m128i tmp4;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
	tmp4 = _mm_slli_si128(*tmp1, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp1 = _mm_xor_si128(*tmp1, tmp4);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
	__m128i tmp2, tmp4;

	tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
	tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
	tmp4 = _mm_slli_si128(*tmp3, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	tmp4 = _mm_slli_si128(tmp4, 0x04);
	*tmp3 = _mm_xor_si128(*tmp3, tmp4);
	*tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
static inline void ExpandAESKey256(uint8_t *keybuf)
{
	__m128i tmp1, tmp2, tmp3, *keys;

	keys = (__m128i *)keybuf;

	tmp1 = _mm_load_si128((__m128i *)keybuf);
	tmp3 = _mm_load_si128((__m128i *)(keybuf + 0x10));

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[2] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[3] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[4] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[5] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[6] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[7] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[8] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[9] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[10] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[11] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[12] = tmp1;
	ExpandAESKey256_sub2(&tmp1, &tmp3);
	keys[13] = tmp3;

	tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
	ExpandAESKey256_sub1(&tmp1, &tmp2);
	keys[14] = tmp1;
}

static void(*const extra_hashes[4])(const void *, size_t, char *) =
{
	hash_extra_blake, hash_extra_groestl, hash_extra_jh, hash_extra_skein
};



static void cn_slow_hash_aesni(void *restrict context, const void *restrict data, size_t length, void *restrict hash)
{
#define ctx ((struct cn_ctx *) context)
	ALIGNED_DECL(uint8_t ExpandedKey[256], 16);
	size_t i;
	__m128i *longoutput, *expkey, *xmminput, b_x;
	ALIGNED_DECL(uint64_t a[2], 16);
	hash_process(&ctx->state.hs, (const uint8_t*)data, length);

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);

	memcpy(ExpandedKey, ctx->state.hs.b, AES_KEY_SIZE);
	ExpandAESKey256(ExpandedKey);

	longoutput = (__m128i *) ctx->long_state;
	expkey = (__m128i *) ExpandedKey;
	xmminput = (__m128i *) ctx->text;

	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
	{
		for (size_t j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}
		_mm_store_si128(&(longoutput[(i >> 4)]), xmminput[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), xmminput[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), xmminput[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), xmminput[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), xmminput[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), xmminput[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), xmminput[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), xmminput[7]);
	}

	for (i = 0; i < 2; i++)
	{
		ctx->a[i] = ((uint64_t *)ctx->state.k)[i] ^ ((uint64_t *)ctx->state.k)[i + 4];
		ctx->b[i] = ((uint64_t *)ctx->state.k)[i + 2] ^ ((uint64_t *)ctx->state.k)[i + 6];
	}

	b_x = _mm_load_si128((__m128i *)ctx->b);
	a[0] = ctx->a[0];
	a[1] = ctx->a[1];

	for (i = 0; likely(i < 0x80000); i++)
	{
		__m128i c_x = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
		__m128i a_x = _mm_load_si128((__m128i *)a);
		ALIGNED_DECL(uint64_t c[2], 16);
		ALIGNED_DECL(uint64_t b[2], 16);
		uint64_t *nextblock, *dst;

		c_x = _mm_aesenc_si128(c_x, a_x);

		_mm_store_si128((__m128i *)c, c_x);

		b_x = _mm_xor_si128(b_x, c_x);
		_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], b_x);

		nextblock = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
		b[0] = nextblock[0];
		b[1] = nextblock[1];

		{
			uint64_t hi, lo;

			lo = mul128(c[0], b[0], &hi);

			a[0] += hi;
			a[1] += lo;
		}
		dst = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
		dst[0] = a[0];
		dst[1] = a[1];

		a[0] ^= b[0];
		a[1] ^= b[1];
		b_x = c_x;
	}

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	memcpy(ExpandedKey, &ctx->state.hs.b[32], AES_KEY_SIZE);
	ExpandAESKey256(ExpandedKey);

	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
	{
		xmminput[0] = _mm_xor_si128(longoutput[(i >> 4)], xmminput[0]);
		xmminput[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], xmminput[1]);
		xmminput[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], xmminput[2]);
		xmminput[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], xmminput[3]);
		xmminput[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], xmminput[4]);
		xmminput[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], xmminput[5]);
		xmminput[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], xmminput[6]);
		xmminput[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], xmminput[7]);

		for (size_t j = 0; j < 10; j++)
		{
			xmminput[0] = _mm_aesenc_si128(xmminput[0], expkey[j]);
			xmminput[1] = _mm_aesenc_si128(xmminput[1], expkey[j]);
			xmminput[2] = _mm_aesenc_si128(xmminput[2], expkey[j]);
			xmminput[3] = _mm_aesenc_si128(xmminput[3], expkey[j]);
			xmminput[4] = _mm_aesenc_si128(xmminput[4], expkey[j]);
			xmminput[5] = _mm_aesenc_si128(xmminput[5], expkey[j]);
			xmminput[6] = _mm_aesenc_si128(xmminput[6], expkey[j]);
			xmminput[7] = _mm_aesenc_si128(xmminput[7], expkey[j]);
		}

	}

	memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	hash_permutation(&ctx->state.hs);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, hash);
}



static void cn_slow_hash_noaesni(void *restrict context, const void *restrict data, size_t length, void *restrict hash)
{

#define ctx ((struct cn_ctx *) context)
	ALIGNED_DECL(uint8_t ExpandedKey[256], 16);
	size_t i;
	__m128i *longoutput, *expkey, *xmminput, b_x;
	ALIGNED_DECL(uint64_t a[2], 16);
	hash_process(&ctx->state.hs, (const uint8_t*)data, length);

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	ctx->aes_ctx = oaes_alloc();
	oaes_key_import_data(ctx->aes_ctx, ctx->state.hs.b, AES_KEY_SIZE);
	memcpy(ExpandedKey, ctx->aes_ctx->key->exp_data, ctx->aes_ctx->key->exp_data_len);

	longoutput = (__m128i *) ctx->long_state;
	expkey = (__m128i *) ExpandedKey;
	xmminput = (__m128i *) ctx->text;


	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
	{
		aesb_pseudo_round((uint8_t *)&xmminput[0], (uint8_t *)&xmminput[0], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[1], (uint8_t *)&xmminput[1], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[2], (uint8_t *)&xmminput[2], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[3], (uint8_t *)&xmminput[3], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[4], (uint8_t *)&xmminput[4], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[5], (uint8_t *)&xmminput[5], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[6], (uint8_t *)&xmminput[6], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[7], (uint8_t *)&xmminput[7], (uint8_t *)expkey);

		_mm_store_si128(&(longoutput[(i >> 4)]), xmminput[0]);
		_mm_store_si128(&(longoutput[(i >> 4) + 1]), xmminput[1]);
		_mm_store_si128(&(longoutput[(i >> 4) + 2]), xmminput[2]);
		_mm_store_si128(&(longoutput[(i >> 4) + 3]), xmminput[3]);
		_mm_store_si128(&(longoutput[(i >> 4) + 4]), xmminput[4]);
		_mm_store_si128(&(longoutput[(i >> 4) + 5]), xmminput[5]);
		_mm_store_si128(&(longoutput[(i >> 4) + 6]), xmminput[6]);
		_mm_store_si128(&(longoutput[(i >> 4) + 7]), xmminput[7]);
	}

	for (i = 0; i < 2; i++)
	{
		ctx->a[i] = ((uint64_t *)ctx->state.k)[i] ^ ((uint64_t *)ctx->state.k)[i + 4];
		ctx->b[i] = ((uint64_t *)ctx->state.k)[i + 2] ^ ((uint64_t *)ctx->state.k)[i + 6];
	}

	b_x = _mm_load_si128((__m128i *)ctx->b);
	a[0] = ctx->a[0];
	a[1] = ctx->a[1];

	for (i = 0; likely(i < 0x80000); i++)
	{
		__m128i c_x = _mm_load_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0]);
		__m128i a_x = _mm_load_si128((__m128i *)a);
		ALIGNED_DECL(uint64_t c[2], 16);
		ALIGNED_DECL(uint64_t b[2], 16);
		uint64_t *nextblock, *dst;

		aesb_single_round((uint8_t *)&c_x, (uint8_t *)&c_x, (uint8_t *)&a_x);

		_mm_store_si128((__m128i *)c, c_x);

		b_x = _mm_xor_si128(b_x, c_x);
		_mm_store_si128((__m128i *)&ctx->long_state[a[0] & 0x1FFFF0], b_x);

		nextblock = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
		b[0] = nextblock[0];
		b[1] = nextblock[1];

		{
			uint64_t hi, lo;

			lo = mul128(c[0], b[0], &hi);

			a[0] += hi;
			a[1] += lo;
		}
		dst = (uint64_t *)&ctx->long_state[c[0] & 0x1FFFF0];
		dst[0] = a[0];
		dst[1] = a[1];

		a[0] ^= b[0];
		a[1] ^= b[1];
		b_x = c_x;
	}

	memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(ctx->aes_ctx, &ctx->state.hs.b[32], AES_KEY_SIZE);
	memcpy(ExpandedKey, ctx->aes_ctx->key->exp_data, ctx->aes_ctx->key->exp_data_len);

	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE)
	{
		xmminput[0] = _mm_xor_si128(longoutput[(i >> 4)], xmminput[0]);
		xmminput[1] = _mm_xor_si128(longoutput[(i >> 4) + 1], xmminput[1]);
		xmminput[2] = _mm_xor_si128(longoutput[(i >> 4) + 2], xmminput[2]);
		xmminput[3] = _mm_xor_si128(longoutput[(i >> 4) + 3], xmminput[3]);
		xmminput[4] = _mm_xor_si128(longoutput[(i >> 4) + 4], xmminput[4]);
		xmminput[5] = _mm_xor_si128(longoutput[(i >> 4) + 5], xmminput[5]);
		xmminput[6] = _mm_xor_si128(longoutput[(i >> 4) + 6], xmminput[6]);
		xmminput[7] = _mm_xor_si128(longoutput[(i >> 4) + 7], xmminput[7]);

		aesb_pseudo_round((uint8_t *)&xmminput[0], (uint8_t *)&xmminput[0], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[1], (uint8_t *)&xmminput[1], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[2], (uint8_t *)&xmminput[2], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[3], (uint8_t *)&xmminput[3], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[4], (uint8_t *)&xmminput[4], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[5], (uint8_t *)&xmminput[5], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[6], (uint8_t *)&xmminput[6], (uint8_t *)expkey);
		aesb_pseudo_round((uint8_t *)&xmminput[7], (uint8_t *)&xmminput[7], (uint8_t *)expkey);

	}

	oaes_free((OAES_CTX **)&ctx->aes_ctx);

	memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
	hash_permutation(&ctx->state.hs);
	extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, hash);
}


INITIALIZER(detect_aes) {
	int ecx;
	int cpuinfo[4];
	__cpuid(cpuinfo, 1);
	ecx = cpuinfo[2];
	cn_slow_hash_fp = (ecx & (1 << 25)) ? &cn_slow_hash_aesni : &cn_slow_hash_noaesni;
}
