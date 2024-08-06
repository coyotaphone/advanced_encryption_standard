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
  //uint8_t y = x ? InvertGF(x) : 0x00ui8;
  //uint8_t z = y ^ 0b01100011;
  //for (int i = 4; i < 8; ++i)
  //  z ^= RotateRight8(y, i);
  //return z;
  static const uint8_t box[256] = {
    0x63ui8, 0x7cui8, 0x77ui8, 0x7bui8, 0xf2ui8, 0x6bui8, 0x6fui8, 0xc5ui8, 0x30ui8, 0x01ui8, 0x67ui8, 0x2bui8, 0xfeui8, 0xd7ui8, 0xabui8, 0x76ui8,
    0xcaui8, 0x82ui8, 0xc9ui8, 0x7dui8, 0xfaui8, 0x59ui8, 0x47ui8, 0xf0ui8, 0xadui8, 0xd4ui8, 0xa2ui8, 0xafui8, 0x9cui8, 0xa4ui8, 0x72ui8, 0xc0ui8,
    0xb7ui8, 0xfdui8, 0x93ui8, 0x26ui8, 0x36ui8, 0x3fui8, 0xf7ui8, 0xccui8, 0x34ui8, 0xa5ui8, 0xe5ui8, 0xf1ui8, 0x71ui8, 0xd8ui8, 0x31ui8, 0x15ui8,
    0x04ui8, 0xc7ui8, 0x23ui8, 0xc3ui8, 0x18ui8, 0x96ui8, 0x05ui8, 0x9aui8, 0x07ui8, 0x12ui8, 0x80ui8, 0xe2ui8, 0xebui8, 0x27ui8, 0xb2ui8, 0x75ui8,
    0x09ui8, 0x83ui8, 0x2cui8, 0x1aui8, 0x1bui8, 0x6eui8, 0x5aui8, 0xa0ui8, 0x52ui8, 0x3bui8, 0xd6ui8, 0xb3ui8, 0x29ui8, 0xe3ui8, 0x2fui8, 0x84ui8,
    0x53ui8, 0xd1ui8, 0x00ui8, 0xedui8, 0x20ui8, 0xfcui8, 0xb1ui8, 0x5bui8, 0x6aui8, 0xcbui8, 0xbeui8, 0x39ui8, 0x4aui8, 0x4cui8, 0x58ui8, 0xcfui8,
    0xd0ui8, 0xefui8, 0xaaui8, 0xfbui8, 0x43ui8, 0x4dui8, 0x33ui8, 0x85ui8, 0x45ui8, 0xf9ui8, 0x02ui8, 0x7fui8, 0x50ui8, 0x3cui8, 0x9fui8, 0xa8ui8,
    0x51ui8, 0xa3ui8, 0x40ui8, 0x8fui8, 0x92ui8, 0x9dui8, 0x38ui8, 0xf5ui8, 0xbcui8, 0xb6ui8, 0xdaui8, 0x21ui8, 0x10ui8, 0xffui8, 0xf3ui8, 0xd2ui8,
    0xcdui8, 0x0cui8, 0x13ui8, 0xecui8, 0x5fui8, 0x97ui8, 0x44ui8, 0x17ui8, 0xc4ui8, 0xa7ui8, 0x7eui8, 0x3dui8, 0x64ui8, 0x5dui8, 0x19ui8, 0x73ui8,
    0x60ui8, 0x81ui8, 0x4fui8, 0xdcui8, 0x22ui8, 0x2aui8, 0x90ui8, 0x88ui8, 0x46ui8, 0xeeui8, 0xb8ui8, 0x14ui8, 0xdeui8, 0x5eui8, 0x0bui8, 0xdbui8,
    0xe0ui8, 0x32ui8, 0x3aui8, 0x0aui8, 0x49ui8, 0x06ui8, 0x24ui8, 0x5cui8, 0xc2ui8, 0xd3ui8, 0xacui8, 0x62ui8, 0x91ui8, 0x95ui8, 0xe4ui8, 0x79ui8,
    0xe7ui8, 0xc8ui8, 0x37ui8, 0x6dui8, 0x8dui8, 0xd5ui8, 0x4eui8, 0xa9ui8, 0x6cui8, 0x56ui8, 0xf4ui8, 0xeaui8, 0x65ui8, 0x7aui8, 0xaeui8, 0x08ui8,
    0xbaui8, 0x78ui8, 0x25ui8, 0x2eui8, 0x1cui8, 0xa6ui8, 0xb4ui8, 0xc6ui8, 0xe8ui8, 0xddui8, 0x74ui8, 0x1fui8, 0x4bui8, 0xbdui8, 0x8bui8, 0x8aui8,
    0x70ui8, 0x3eui8, 0xb5ui8, 0x66ui8, 0x48ui8, 0x03ui8, 0xf6ui8, 0x0eui8, 0x61ui8, 0x35ui8, 0x57ui8, 0xb9ui8, 0x86ui8, 0xc1ui8, 0x1dui8, 0x9eui8,
    0xe1ui8, 0xf8ui8, 0x98ui8, 0x11ui8, 0x69ui8, 0xd9ui8, 0x8eui8, 0x94ui8, 0x9bui8, 0x1eui8, 0x87ui8, 0xe9ui8, 0xceui8, 0x55ui8, 0x28ui8, 0xdfui8,
    0x8cui8, 0xa1ui8, 0x89ui8, 0x0dui8, 0xbfui8, 0xe6ui8, 0x42ui8, 0x68ui8, 0x41ui8, 0x99ui8, 0x2dui8, 0x0fui8, 0xb0ui8, 0x54ui8, 0xbbui8, 0x16ui8
  };
  return box[x];
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
  static const uint32_t Rcon[10] = {
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
  //uint8_t y = 0x00ui8;
  //while (SBox(y) != x)
  //  ++y;
  //return y;
  static const uint8_t box[256] = {
    0x52ui8, 0x09ui8, 0x6aui8, 0xd5ui8, 0x30ui8, 0x36ui8, 0xa5ui8, 0x38ui8, 0xbfui8, 0x40ui8, 0xa3ui8, 0x9eui8, 0x81ui8, 0xf3ui8, 0xd7ui8, 0xfbui8,
    0x7cui8, 0xe3ui8, 0x39ui8, 0x82ui8, 0x9bui8, 0x2fui8, 0xffui8, 0x87ui8, 0x34ui8, 0x8eui8, 0x43ui8, 0x44ui8, 0xc4ui8, 0xdeui8, 0xe9ui8, 0xcbui8,
    0x54ui8, 0x7bui8, 0x94ui8, 0x32ui8, 0xa6ui8, 0xc2ui8, 0x23ui8, 0x3dui8, 0xeeui8, 0x4cui8, 0x95ui8, 0x0bui8, 0x42ui8, 0xfaui8, 0xc3ui8, 0x4eui8,
    0x08ui8, 0x2eui8, 0xa1ui8, 0x66ui8, 0x28ui8, 0xd9ui8, 0x24ui8, 0xb2ui8, 0x76ui8, 0x5bui8, 0xa2ui8, 0x49ui8, 0x6dui8, 0x8bui8, 0xd1ui8, 0x25ui8,
    0x72ui8, 0xf8ui8, 0xf6ui8, 0x64ui8, 0x86ui8, 0x68ui8, 0x98ui8, 0x16ui8, 0xd4ui8, 0xa4ui8, 0x5cui8, 0xccui8, 0x5dui8, 0x65ui8, 0xb6ui8, 0x92ui8,
    0x6cui8, 0x70ui8, 0x48ui8, 0x50ui8, 0xfdui8, 0xedui8, 0xb9ui8, 0xdaui8, 0x5eui8, 0x15ui8, 0x46ui8, 0x57ui8, 0xa7ui8, 0x8dui8, 0x9dui8, 0x84ui8,
    0x90ui8, 0xd8ui8, 0xabui8, 0x00ui8, 0x8cui8, 0xbcui8, 0xd3ui8, 0x0aui8, 0xf7ui8, 0xe4ui8, 0x58ui8, 0x05ui8, 0xb8ui8, 0xb3ui8, 0x45ui8, 0x06ui8,
    0xd0ui8, 0x2cui8, 0x1eui8, 0x8fui8, 0xcaui8, 0x3fui8, 0x0fui8, 0x02ui8, 0xc1ui8, 0xafui8, 0xbdui8, 0x03ui8, 0x01ui8, 0x13ui8, 0x8aui8, 0x6bui8,
    0x3aui8, 0x91ui8, 0x11ui8, 0x41ui8, 0x4fui8, 0x67ui8, 0xdcui8, 0xeaui8, 0x97ui8, 0xf2ui8, 0xcfui8, 0xceui8, 0xf0ui8, 0xb4ui8, 0xe6ui8, 0x73ui8,
    0x96ui8, 0xacui8, 0x74ui8, 0x22ui8, 0xe7ui8, 0xadui8, 0x35ui8, 0x85ui8, 0xe2ui8, 0xf9ui8, 0x37ui8, 0xe8ui8, 0x1cui8, 0x75ui8, 0xdfui8, 0x6eui8,
    0x47ui8, 0xf1ui8, 0x1aui8, 0x71ui8, 0x1dui8, 0x29ui8, 0xc5ui8, 0x89ui8, 0x6fui8, 0xb7ui8, 0x62ui8, 0x0eui8, 0xaaui8, 0x18ui8, 0xbeui8, 0x1bui8,
    0xfcui8, 0x56ui8, 0x3eui8, 0x4bui8, 0xc6ui8, 0xd2ui8, 0x79ui8, 0x20ui8, 0x9aui8, 0xdbui8, 0xc0ui8, 0xfeui8, 0x78ui8, 0xcdui8, 0x5aui8, 0xf4ui8,
    0x1fui8, 0xddui8, 0xa8ui8, 0x33ui8, 0x88ui8, 0x07ui8, 0xc7ui8, 0x31ui8, 0xb1ui8, 0x12ui8, 0x10ui8, 0x59ui8, 0x27ui8, 0x80ui8, 0xecui8, 0x5fui8,
    0x60ui8, 0x51ui8, 0x7fui8, 0xa9ui8, 0x19ui8, 0xb5ui8, 0x4aui8, 0x0dui8, 0x2dui8, 0xe5ui8, 0x7aui8, 0x9fui8, 0x93ui8, 0xc9ui8, 0x9cui8, 0xefui8,
    0xa0ui8, 0xe0ui8, 0x3bui8, 0x4dui8, 0xaeui8, 0x2aui8, 0xf5ui8, 0xb0ui8, 0xc8ui8, 0xebui8, 0xbbui8, 0x3cui8, 0x83ui8, 0x53ui8, 0x99ui8, 0x61ui8,
    0x17ui8, 0x2bui8, 0x04ui8, 0x7eui8, 0xbaui8, 0x77ui8, 0xd6ui8, 0x26ui8, 0xe1ui8, 0x69ui8, 0x14ui8, 0x63ui8, 0x55ui8, 0x21ui8, 0x0cui8, 0x7dui8
  };
  return box[x];
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
