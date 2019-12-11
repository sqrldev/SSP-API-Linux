
// blowfish.h

// Written by Andrew Carter (2008)

#ifndef BLOWFISH_H_
#define BLOWFISH_H_

typedef unsigned int BF_ULONG;

typedef struct blowfish_context_t_ {
	BF_ULONG pbox[256];
	BF_ULONG sbox[4][256];
} blowfish_context_t;

void blowfish_encryptblock (blowfish_context_t *ctx, BF_ULONG  *hi,  BF_ULONG *lo);
void blowfish_decryptblock (blowfish_context_t *ctx, BF_ULONG  *hi,  BF_ULONG *lo);
void blowfish_initiate     (blowfish_context_t *ctx, const void *keyparam, unsigned int  keybytes);
void blowfish_clean        (blowfish_context_t *ctx);

//extern const BF_ULONG ORIG_P[18];
//extern const BF_ULONG ORIG_S[4][256];

#endif
