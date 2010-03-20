// custom math routines for shallot

#include "math.h"

void int_pow(uint32_t base, uint8_t pwr, uint64_t *out) { // integer pow()
  *out = (uint64_t)base;
  uint8_t round = 1;
  for(; round < pwr; round++)
    *out *= base;
}

// LCM for BIGNUMs
uint8_t BN_lcm(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *gcd, BN_CTX *ctx) {
  BIGNUM *tmp = BN_CTX_get(ctx);
  if(!BN_div(tmp, NULL, a, gcd, ctx))
    return 0;
  if(!BN_mul(r, b, tmp, ctx))
    return 0;
  return 1;
}

uint8_t sane_key(RSA *rsa) { // checks sanity of a RSA key (PKCS#1 v2.1)
  uint8_t sane = 1;

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *p1     = BN_CTX_get(ctx), // p - 1
         *q1     = BN_CTX_get(ctx), // q - 1
         *chk    = BN_CTX_get(ctx), // storage to run checks with
         *gcd    = BN_CTX_get(ctx), // GCD(p - 1, q - 1)
         *lambda = BN_CTX_get(ctx); // LCM(p - 1, q - 1)

  BN_sub(p1, rsa->p, BN_value_one()); // p - 1
  BN_sub(q1, rsa->q, BN_value_one()); // q - 1
  BN_gcd(gcd, p1, q1, ctx);           // gcd(p - 1, q - 1)
  BN_lcm(lambda, p1, q1, gcd, ctx);   // lamba(n)

  BN_gcd(chk, lambda, rsa->e, ctx); // check if e is coprime to lambda(n)
  if(!BN_is_one(chk))
    sane = 0;

  // check if public exponent e is less than n - 1
  BN_sub(chk, rsa->e, rsa->n); // subtract n from e to avoid checking BN_is_zero
  if(!chk->neg)
    sane = 0;

  BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);    // d
  BN_mod(rsa->dmp1, rsa->d, p1, ctx);             // d mod (p - 1)
  BN_mod(rsa->dmq1, rsa->d, q1, ctx);             // d mod (q - 1)
  BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx); // q ^ -1 mod p
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  // this is excessive but you're better off safe than (very) sorry
  // in theory this should never be true unless I made a mistake ;)
  if((RSA_check_key(rsa) != 1) && sane) {
    fprintf(stderr, "WARNING: Key looked okay, but OpenSSL says otherwise!\n");
    sane = 0;
  }

  return sane;
}

