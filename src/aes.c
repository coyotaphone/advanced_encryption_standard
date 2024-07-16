#include "../include/aes.h"

typedef uint8_t state_t[4][4];

typedef uint32_t exp128_t[4 * (10 + 1)];
typedef uint32_t exp192_t[4 * (12 + 1)];
typedef uint32_t exp256_t[4 * (14 + 1)];

typedef uint32_t* key_t, * exp_t;
typedef uint32_t rkey_t[4];

static inline uint32_t RotateRight(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint8_t RotateRight8(uint8_t x, int n) { return (x >> n) | (x << (8 - n)); }

static inline uint8_t xTimes(uint8_t x) { return x & 0b10000000 ? (x << 1) ^ 0b100011011 : x << 1; }

static uint8_t MultiplyGF(uint8_t x, uint8_t y) {
  uint8_t z = 0x00ui8;
  for (int i = 0; i < 8; ++i) {
    z = xTimes(z);
    if (y & 0b10000000)
      z ^= x;
    y <<= 1;
  }
  return z;
}

static uint8_t InvertGF(uint8_t x) {
  uint8_t y = MultiplyGF(x, x);
  x = MultiplyGF(y, y);
  y = MultiplyGF(y, x);
  for (int i = 0; i < 5; ++i) {
    x = MultiplyGF(x, x);
    y = MultiplyGF(y, x);
  }
  return y;
}

static uint8_t SBox(uint8_t x) {
  uint8_t y = x ? InvertGF(x) : 0x00ui8;
  uint8_t z = y ^ 0b01100011;
  for (int i = 4; i < 8; ++i)
    z ^= RotateRight8(y, i);
  return z;
}

static uint32_t SubWord(uint32_t x) {
  for (uint8_t* ptr = (uint8_t*)&x, *end = ptr + 4; ptr < end; ++ptr)
    *ptr = SBox(*ptr);
  return x;
}

static void SubBytes(state_t state) {
  for (uint8_t* ptr = *state, *end = ptr + 16; ptr < end; ++ptr)
    *ptr = SBox(*ptr);
}

static void ShiftRows(state_t state) {
  uint32_t* ptr = (uint32_t*)*state + 1;
  for (int n = 8; n < 32; n += 8)
    *ptr++ = RotateRight(*ptr, n);
}

static void MixColumns(state_t state, uint32_t a) {
  for (int c = 0; c < 4; ++c) {
    uint8_t s[4] = { state[0][c], state[1][c], state[2][c], state[3][c] };
    for (uint8_t* ptr = *state + c, *end = *state + 16; ptr < end; ptr += 4) {
      uint8_t* aptr = (uint8_t*)&a;
      uint8_t* sptr = s;
      a = RotateRight(a, 24);
      *ptr = MultiplyGF(*aptr, *sptr);
      for (int i = 0; i < 3; ++i)
        *ptr ^= MultiplyGF(*++aptr, *++sptr);
    }
  }
}

static void AddRoundKey(state_t state, const rkey_t w) {
  const uint8_t* ptr = (const uint8_t*)w + 3;
  for (int c = 0; c < 4; ++c) {
    for (int r = 0; r < 4; ++r)
      state[r][c] ^= *ptr--;
    ptr += 8;
  }
}

static void KeyExpansion(const key_t key, int Nk, int Nr, exp_t exp) {
  uint32_t Rcon[10] = {
    0x01000000ui32, 0x02000000ui32, 0x04000000ui32, 0x08000000ui32, 0x10000000ui32,
    0x20000000ui32, 0x40000000ui32, 0x80000000ui32, 0x1b000000ui32, 0x36000000ui32
  };
  memcpy(exp, key, Nk * sizeof(uint32_t));
  for (int i = Nk, j = 4 * (Nr + 1); i < j; ++i) {
    uint32_t temp = exp[i - 1];
    int k = i % Nk;
    if (!k)
      temp = SubWord(RotateRight(temp, 24)) ^ Rcon[i / Nk - 1];
    else
      if (Nk > 6 && k == 4)
        temp = SubWord(temp);
    exp[i] = exp[i - Nk] ^ temp;
  }
}

static void Cipher(const block128_t in, int Nr, exp_t w, block128_t out) {
  state_t state;
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r)
      state[r][c] = *in++;
  rkey_t rkey;
  memcpy(rkey, w, sizeof(rkey_t));
  AddRoundKey(state, rkey);
  while (--Nr) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state, 0x02010103ui32);
    memcpy(rkey, w += 4, sizeof(rkey_t));
    AddRoundKey(state, rkey);
  }
  SubBytes(state);
  ShiftRows(state);
  memcpy(rkey, w += 4, sizeof(rkey_t));
  AddRoundKey(state, rkey);
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r)
      *out++ = state[r][c];
}

bool AES128(const block128_t in, const key128_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp128_t w;
  KeyExpansion((const key_t)key, 4, 10, w);
  Cipher(in, 10, w, out);
  return true;
}

bool AES192(const block128_t in, const key192_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp192_t w;
  KeyExpansion((const key_t)key, 6, 12, w);
  Cipher(in, 12, w, out);
  return true;
}

bool AES256(const block128_t in, const key256_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp256_t w;
  KeyExpansion((const key_t)key, 8, 14, w);
  Cipher(in, 14, w, out);
  return true;
}

static void InvShiftRows(state_t state) {
  uint32_t* ptr = (uint32_t*)*state + 1;
  for (int n = 24; n > 0; n -= 8)
    *ptr++ = RotateRight(*ptr, n);
}

static uint8_t InvSBox(uint8_t x) {
  uint8_t y = 0x00ui8;
  while (SBox(y) != x)
    ++y;
  return y;
}

static void InvSubBytes(state_t state) {
  for (uint8_t* ptr = *state, *end = ptr + 16; ptr < end; ++ptr)
    *ptr = InvSBox(*ptr);
}

static void InvCipher(const block128_t in, int Nr, exp_t w, block128_t out) {
  state_t state;
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r)
      state[r][c] = *in++;
  rkey_t rkey;
  memcpy(rkey, w += 4 * Nr, sizeof(rkey_t));
  AddRoundKey(state, rkey);
  while (--Nr) {
    InvShiftRows(state);
    InvSubBytes(state);
    memcpy(rkey, w -= 4, sizeof(rkey_t));
    AddRoundKey(state, rkey);
    MixColumns(state, 0x0e090d0bui32);
  }
  InvShiftRows(state);
  InvSubBytes(state);
  memcpy(rkey, w -= 4, sizeof(rkey_t));
  AddRoundKey(state, rkey);
  for (int c = 0; c < 4; ++c)
    for (int r = 0; r < 4; ++r)
      *out++ = state[r][c];
}

bool InvAES128(const block128_t in, const key128_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp128_t dw;
  KeyExpansion((const key_t)key, 4, 10, dw);
  InvCipher(in, 10, dw, out);
  return true;
}

bool InvAES192(const block128_t in, const key192_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp192_t dw;
  KeyExpansion((const key_t)key, 6, 12, dw);
  InvCipher(in, 12, dw, out);
  return true;
}

bool InvAES256(const block128_t in, const key256_t key, block128_t out) {
  if (!in || !key || !out)
    return false;
  exp256_t dw;
  KeyExpansion((const key_t)key, 8, 14, dw);
  InvCipher(in, 14, dw, out);
  return true;
}
