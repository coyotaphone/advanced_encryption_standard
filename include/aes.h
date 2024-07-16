#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <stdlib.h>
#include <string.h>

typedef uint8_t block128_t[128 / 8];

typedef uint32_t key128_t[128 / 32];
typedef uint32_t key192_t[192 / 32];
typedef uint32_t key256_t[256 / 32];

bool AES128(const block128_t in, const key128_t key, block128_t out);
bool AES192(const block128_t in, const key192_t key, block128_t out);
bool AES256(const block128_t in, const key256_t key, block128_t out);

bool InvAES128(const block128_t in, const key128_t key, block128_t out);
bool InvAES192(const block128_t in, const key192_t key, block128_t out);
bool InvAES256(const block128_t in, const key256_t key, block128_t out);

#ifdef __cplusplus
}
#endif
