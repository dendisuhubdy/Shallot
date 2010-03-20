/* program: onionhash
 * version: 0.0.1 beta (tested by the friendly guys at ORC)
 * purpose: brute-force customized SHA1-onionhashes of RSA-keys
 * license: code and ideas were taken from those bright guys (thanks!):
 *          * Plasmoid (The Hacker's Choice)
 *          * Roger Dingledine (Tor Project)
 *          * Nick Mathewson (Tor Project)
 *          * Eric Young (OpenSSL Project)
 * contact: send bug reports and beer to <bebop@xjvhmi7haf2lpb66.onion>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <regex.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>

/* crypt constants */
#define REGEX_COMP_LMAX 64
#define SHA1_DIGEST_LEN 20
#define RSA_KEYS_BITLEN 1024
#define RSA_PK_EXPONENT 65537
#define BASE32_NUM_BITS SHA1_DIGEST_LEN/2*8
#define BASE32_ONIONLEN SHA1_DIGEST_LEN/2*8/5+1
#define BASE32_ALPHABET "abcdefghijklmnopqrstuvwxyz234567"

/* error codes */
#define X_WRONG_NUMARGS 1
#define X_REGEX_COMPILE 2
#define X_SIG_INTERRUPT 3

/* global variables */
unsigned long loop = 0; /* brute force attempt counter */


/* how to use this stuff */
void usage(void)
{
  printf("Usage: onionhash pattern\n"); /* keep it simple, stupid */
  printf("base32 alphabet allows letters [a-z] and digits [2-7]\n");
  printf("pattern can be a POSIX-style regular expression, e.g.\n");
  printf("  xxx        must contain \"xxx\"\n");
  printf("  bar$       must end with \"bar\"\n");
  printf("  ^foo       must begin with \"foo\"\n");
  printf("  b[a4]r     may contain leetspeech ;)\n");
  printf("  ^ab|^cd    must begin with \"ab\" or \"cd\"\n");
  printf("  [a-z]{16}  must contain letters only, no digits\n");
  exit(X_WRONG_NUMARGS);
}

/* exit when receiving CTRL-C */
void terminate(int signum)
{
  printf("\rCaught SIGINT after %ld tries - exiting.\n", loop+1);
  exit(X_SIG_INTERRUPT);
}

/* base32 encode onionhash */
void base32_onion(char *dst, char *src)
{
  unsigned int i, bit, v, u;
  for (i=0, bit=0; bit < BASE32_NUM_BITS; ++i, bit+=5)
  {
    v = ((uint8_t)src[bit/8]) << 8;
    if (bit+5 < BASE32_NUM_BITS) v += (uint8_t)src[(bit/8)+1];
    u = (v >> (11-(bit%8))) & 0x1F;
    dst[i] = BASE32_ALPHABET[u];
  }
  dst[i] = '\0';
}

/* pretty print onionhash */
void print_onion(char *onion)
{
  int i;
  char *s;
  asprintf(&s, "Found matching pattern after %ld tries: %s.onion", loop, onion);
  for (i=0; i<strlen(s); i++)
    printf("-");
  printf("\n%s\n", s);
  for (i=0; i<strlen(s); i++)
    printf("-");
  printf("\n");
}

/* print PEM formated RSA key */
void print_prkey(RSA *rsa)
{
  BUF_MEM *buf;
  BIO *b = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(b, rsa, NULL, NULL, 0, NULL, NULL);
  BIO_get_mem_ptr(b, &buf);
  BIO_set_close(b, BIO_NOCLOSE);
  BIO_free(b);
  char *dst = malloc(buf->length+1);
  strncpy(dst, buf->data, buf->length);
  dst[buf->length] = '\0';
  printf("%s", dst);
  BUF_MEM_free(buf);
}

/* calculate SHA1 hash of RSA-1024 keys until pattern is matched */
void brute_force_onion(regex_t *regex, char *onion, RSA *rsa)
{
  int len;
  char buf[SHA1_DIGEST_LEN];
  unsigned char *pem, *tmp = malloc(RSA_KEYS_BITLEN);
  BN_CTX *ctx = BN_CTX_new(); BN_CTX_start(ctx);
  BIGNUM *phi = BN_CTX_get(ctx), *p = BN_CTX_get(ctx), *q = BN_CTX_get(ctx);
  /* p, q and phi(n) are only calculated once */
  BN_sub(p, rsa->p, BN_value_one());
  BN_sub(q, rsa->q, BN_value_one());
  BN_mul(phi, p, q, ctx);

  do /* main loop - no sanity checks in here for performance reasons... */
  {  /* calculate next RSA private key */
    BN_add_word(rsa->e, 2L);
    rsa->d = BN_mod_inverse(rsa->d, rsa->e, phi, ctx);
    if ((rsa->d) == NULL) /* seems to happen from time to time... */
      continue;
    BN_mod(rsa->dmp1, rsa->d, p, ctx);
    BN_mod(rsa->dmq1, rsa->d, q, ctx);
    /* convert RSA key to PEM format */
    pem = tmp = malloc(RSA_KEYS_BITLEN);
    len = i2d_RSAPublicKey(rsa, &tmp);
    pem[len] = '\0';
    /* compute SHA1 digest of PEM-formated RSA key */
    SHA1((const unsigned char*)pem, len, (unsigned char*)buf);
    free(pem);
    /* base32 encode SHA1 digest */
    base32_onion(onion, buf);
    loop++;
  } while (regexec(regex, onion, 0, 0, 0)); /* check for match */

  /* free(kevin); oh wait..he's already been released */
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
}

/* onions are fun, here we go */
int main(int argc, char *argv[])
{
  regex_t *regex = malloc(REGEX_COMP_LMAX);
  char onion[BASE32_ONIONLEN], *pattern = argv[1];
  /* only the first key is securely generated */
  RSA *rsa = RSA_generate_key(RSA_KEYS_BITLEN, RSA_PK_EXPONENT, NULL, NULL);

  /* set signal handler to terminate() on CTRL-C */
  signal(SIGINT, terminate);

  if (argc <= 1)
    usage(); /* not enough arguments */
  /*  compile regular expression from argument */
  if (regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB))
    return X_REGEX_COMPILE;

  /* crunch untilng regex pattern is found */
  brute_force_onion(regex, onion, rsa);

  /* print results */
  print_onion(onion);
  print_prkey(rsa);
  regfree(regex);
  RSA_free(rsa);
  return 0;
}
