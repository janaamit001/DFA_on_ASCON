#include <stdio.h>
#include "api.h"
#include "permutations.h"

#define RATE (128 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 8
#define IV                                                        \
  ((u64)(8 * (CRYPTO_KEYBYTES)) << 56 | (u64)(8 * (RATE)) << 48 | \
   (u64)(PA_ROUNDS) << 40 | (u64)(PB_ROUNDS) << 32)

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }

  const u64 K0 = BYTES_TO_U64(k, 8);
  const u64 K1 = BYTES_TO_U64(k + 8, 8);
  const u64 N0 = BYTES_TO_U64(npub, 8);
  const u64 N1 = BYTES_TO_U64(npub + 8, 8);
  state s;
  u64 c0, c1;
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;

  // initialization
  s.x0 = IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  printstate("initial value:", s);
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization:", s);

  // process associated data
  if (adlen) {
    while (adlen >= RATE) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, 8);
      P8(&s);
      adlen -= RATE;
      ad += RATE;
    }
    if (adlen >= 8) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, adlen - 8);
      s.x1 ^= 0x80ull << (56 - 8 * (adlen - 8));
    } else {
      s.x0 ^= BYTES_TO_U64(ad, adlen);
      s.x0 ^= 0x80ull << (56 - 8 * adlen);
    }
    P8(&s);
  }
  s.x4 ^= 1;
  printstate("process associated data:", s);

  // process plaintext
  clen -= CRYPTO_ABYTES;
  while (clen >= RATE) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, 8);
    s.x0 = c0;
    s.x1 = c1;
    P8(&s);
    clen -= RATE;
    m += RATE;
    c += RATE;
  }
  if (clen >= 8) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, clen - 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, clen - 8);
    s.x0 = c0;
    s.x1 &= ~BYTE_MASK(clen - 8);
    s.x1 |= c1;
    s.x1 ^= 0x80ull << (56 - 8 * (clen - 8));
  } else {
    c0 = BYTES_TO_U64(c, clen);
    U64_TO_BYTES(m, s.x0 ^ c0, clen);
    s.x0 &= ~BYTE_MASK(clen);
    s.x0 |= c0;
    s.x0 ^= 0x80ull << (56 - 8 * clen);
  }
  c += clen;
  printstate("process plaintext:", s);

  // finalization
  s.x2 ^= K0;
  s.x3 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization:", s);

  // verify tag
  if (BYTES_TO_U64(c, 8) != s.x3 || BYTES_TO_U64(c + 8, 8) != s.x4) {
    *mlen = 0;
    return -1;
  }

  return 0;
}

int crypto_aead_decrypt_fault(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k, short c_pos, short r_pos) {
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }

  const u64 K0 = BYTES_TO_U64(k, 8);
  const u64 K1 = BYTES_TO_U64(k + 8, 8);
  const u64 N0 = BYTES_TO_U64(npub, 8);
  const u64 N1 = BYTES_TO_U64(npub + 8, 8);
  state s;
  u64 c0, c1;
  unsigned char ftag[16] = {0};
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;

  // initialization
  s.x0 = IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  printstate("initial value:", s);
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization:", s);

  // process associated data
  if (adlen) {
    while (adlen >= RATE) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, 8);
      P8(&s);
      adlen -= RATE;
      ad += RATE;
    }
    if (adlen >= 8) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, adlen - 8);
      s.x1 ^= 0x80ull << (56 - 8 * (adlen - 8));
    } else {
      s.x0 ^= BYTES_TO_U64(ad, adlen);
      s.x0 ^= 0x80ull << (56 - 8 * adlen);
    }
    P8(&s);
  }
  s.x4 ^= 1;
  printstate("process associated data:", s);

  // process plaintext
  clen -= CRYPTO_ABYTES;
  while (clen >= RATE) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, 8);
    s.x0 = c0;
    s.x1 = c1;
    P8(&s);
    clen -= RATE;
    m += RATE;
    c += RATE;
  }
  if (clen >= 8) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, clen - 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, clen - 8);
    s.x0 = c0;
    s.x1 &= ~BYTE_MASK(clen - 8);
    s.x1 |= c1;
    s.x1 ^= 0x80ull << (56 - 8 * (clen - 8));
  } else {
    c0 = BYTES_TO_U64(c, clen);
    U64_TO_BYTES(m, s.x0 ^ c0, clen);
    s.x0 &= ~BYTE_MASK(clen);
    s.x0 |= c0;
    s.x0 ^= 0x80ull << (56 - 8 * clen);
  }
  c += clen;
  printstate("process plaintext:", s);
  
  //s.x0 ^= 0x8000000000000000;

  // finalization
  s.x2 ^= K0;
  s.x3 ^= K1;
  P12_fault(&s, c_pos, r_pos);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization:", s);
  
  U64_TO_BYTES(ftag, s.x3, 8);
  U64_TO_BYTES(ftag+8, s.x4, 8);
  
  /*printf("faulty Tag::\n");
  for( short i = 0; i < 16; ++i )
	printf("%02x ", ftag[ i ]);
  printf("\n");*/
  // verify tag
  if (BYTES_TO_U64(c, 8) != s.x3 || BYTES_TO_U64(c + 8, 8) != s.x4) {
    *mlen = 0;
    return -1;
  }

  return 0;
}

int crypto_aead_decrypt_fault_bit_set(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k, short c_pos, short r_pos) {
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }

  const u64 K0 = BYTES_TO_U64(k, 8);
  const u64 K1 = BYTES_TO_U64(k + 8, 8);
  const u64 N0 = BYTES_TO_U64(npub, 8);
  const u64 N1 = BYTES_TO_U64(npub + 8, 8);
  state s;
  u64 c0, c1;
  unsigned char ftag[16] = {0};
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;

  // initialization
  s.x0 = IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  printstate("initial value:", s);
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("initialization:", s);

  // process associated data
  if (adlen) {
    while (adlen >= RATE) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, 8);
      P8(&s);
      adlen -= RATE;
      ad += RATE;
    }
    if (adlen >= 8) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      s.x1 ^= BYTES_TO_U64(ad + 8, adlen - 8);
      s.x1 ^= 0x80ull << (56 - 8 * (adlen - 8));
    } else {
      s.x0 ^= BYTES_TO_U64(ad, adlen);
      s.x0 ^= 0x80ull << (56 - 8 * adlen);
    }
    P8(&s);
  }
  s.x4 ^= 1;
  printstate("process associated data:", s);

  // process plaintext
  clen -= CRYPTO_ABYTES;
  while (clen >= RATE) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, 8);
    s.x0 = c0;
    s.x1 = c1;
    P8(&s);
    clen -= RATE;
    m += RATE;
    c += RATE;
  }
  if (clen >= 8) {
    c0 = BYTES_TO_U64(c, 8);
    c1 = BYTES_TO_U64(c + 8, clen - 8);
    U64_TO_BYTES(m, s.x0 ^ c0, 8);
    U64_TO_BYTES(m + 8, s.x1 ^ c1, clen - 8);
    s.x0 = c0;
    s.x1 &= ~BYTE_MASK(clen - 8);
    s.x1 |= c1;
    s.x1 ^= 0x80ull << (56 - 8 * (clen - 8));
  } else {
    c0 = BYTES_TO_U64(c, clen);
    U64_TO_BYTES(m, s.x0 ^ c0, clen);
    s.x0 &= ~BYTE_MASK(clen);
    s.x0 |= c0;
    s.x0 ^= 0x80ull << (56 - 8 * clen);
  }
  c += clen;
  printstate("process plaintext:", s);
  
  //s.x0 ^= 0x8000000000000000;

  // finalization
  s.x2 ^= K0;
  s.x3 ^= K1;
  P12_fault_bs(&s, c_pos, r_pos);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("finalization:", s);
  
  U64_TO_BYTES(ftag, s.x3, 8);
  U64_TO_BYTES(ftag+8, s.x4, 8);
  
  /*printf("faulty Tag::\n");
  for( short i = 0; i < 16; ++i )
	printf("%02x ", ftag[ i ]);
  printf("\n");*/
  // verify tag
  if (BYTES_TO_U64(c, 8) != s.x3 || BYTES_TO_U64(c + 8, 8) != s.x4) {
    *mlen = 0;
    return -1;
  }

  return 0;
}

