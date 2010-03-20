// printing functions for shallot

#include "config.h"

#include "print.h"
#include "defines.h"
#include "globals.h"

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

void base32_onion(char *dst, unsigned char *src) { // base32 encode hash
  uint16_t i, bit, v, u;
  for(i = 0, bit = 0; bit < BASE32_NUM_BITS; ++i, bit += 5) {
    v = ((uint8_t)src[bit/8]) << 8;
    if(bit+5 < BASE32_NUM_BITS) v += (uint8_t)src[(bit/8)+1];
    u = (v >> (11-(bit%8))) & 0x1F;
    dst[i] = BASE32_ALPHABET[u];
  }
  dst[i] = '\0';
}

void print_onion(char *onion) { // pretty print hash
  uint8_t i;
  char *s;
  #ifdef GENERIC
  s = malloc(PRINT_ONION_MAX);
  snprintf(s, PRINT_ONION_MAX, PRINT_ONION_STR, loop, onion);
  #else
  asprintf(&s, PRINT_ONION_STR, loop, onion);
  #endif
  for(i=0; i<strlen(s); i++)
    printf("-"); // TODO: use fputc()?
  printf("\n%s\n", s);
  for(i=0; i<strlen(s); i++)
    printf("-"); // TODO: use fputc()?
  printf("\n");
  free(s);
}

void print_prkey(RSA *rsa) { // print PEM formated RSA key
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

