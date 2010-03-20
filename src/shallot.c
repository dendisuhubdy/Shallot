/* program: shallot (based on the popular onionhash program by Bebop)
 * version: 0.0.1
 * purpose: brute-force customized SHA1-hashes of RSA keys for Tor's
 *          .onion namespace
 * license: OSI-approved MIT License
 * credits: Bebop, for onionhash, which credits the following:
 *          - Plasmoid         (The Hacker's Choice)
 *          - Roger Dingledine (Tor Project)
 *          - Nick Mathewson   (Tor Project)
 *          - Eric Young       (OpenSSL Project)
 * contact: send bug reports to < at  dot onion>
 */

/* TODO:
 * - finish all TODOs
 */

// defines LINUX_PORT should we (unfortunately) be on linux...
#include "config.h"

#define _GNU_SOURCE

#ifdef LINUX_PORT
// Linux specific headers
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#endif

#include <stdio.h>
#include <regex.h>
#include <netdb.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>

// crypt constants
#define REGEX_COMP_LMAX 64
#define SHA1_DIGEST_LEN 20
#define RSA_KEYS_BITLEN 1024
#define RSA_PK_EXPONENT 65537
#define BASE32_NUM_BITS SHA1_DIGEST_LEN/2*8
#define BASE32_ONIONLEN SHA1_DIGEST_LEN/2*8/5+1
#define BASE32_ALPHABET "abcdefghijklmnopqrstuvwxyz234567"

#ifdef BSD
  // BSD constants
  #define SYSCTL_ID_CPUS "hw.ncpu"
#elif defined(LINUX_PORT)
  // Linux constants (lol no API)
  #define CPUINFO_BUF_SIZE 1024
  #define CPUINFO_PATH "/proc/cpuinfo"
  #define CPUINFO_PROC_STR "processor"
  #define CPUINFO_PROC_STR_LEN 9 // don't include trailing NULL
  // constant sanity checking
  #if CPUINFO_BUF_SIZE < 256
    #error CPUINFO_BUFFER_SIZE set too small.  Please make it bigger.
  #elif CPUINFO_BUF_SIZE > 32767
    #error CPUINFO_BUFFER_SIZE set too large.  Please make it smaller.
  #endif
#else // we won't build blindly!
  #error Don't know what OS we're building for.  Did you run configure?
#endif

// error codes
#define X_WRONG_NUMARGS 1
#define X_REGEX_COMPILE 2
#define X_SIG_INTERRUPT 3
#define X_YOURE_UNLUCKY 4
#define X_KEY_GEN_FAILS 5
#define X_THREAD_CREATE 6

#ifdef BSD
// BSD specific defines
#define X_SYSCTLBN_FAIL 7

#elif defined(LINUX_PORT)
// Linux specific defines
#define X_BAD_FILE_DESC 7
#define X_ABNORMAL_READ 8
#endif


// global variables
unsigned long long loop = 0; // brute force attempt counter
pthread_t lucky_thread;      // the lucky thread finding the key
uint8_t found = 0;           // async thread killing
regex_t *regex;              // regular expression

// how to use this stuff
void usage(void) {
  printf("Usage: shallot <pattern>\n"); // keep it simple, stupid
  printf("base32 alphabet allows letters [a-z] and digits [2-7]\n");
  printf("pattern can be a POSIX-style regular expression, e.g.\n");
  printf("  xxx           must contain 'xxx'\n");
  printf("  bar$          must end with 'bar'\n");
  printf("  ^foo          must begin with 'foo'\n");
  printf("  b[a4]r        may contain leetspeech ;)\n");
  printf("  ^ab|^cd       must begin with 'ab' or 'cd'\n");
  printf("  [a-z]{16}     must contain letters only, no digits\n");
  printf("  ^dusk.*dawn$  must begin with 'dusk' and end with 'dawn'\n");
  printf("Version: %s\n", VERSION);
  exit(X_WRONG_NUMARGS);
}

// our big error handling/reporting function
void error(int32_t code) {
  switch(code) {
    case X_REGEX_COMPILE: {
      fprintf(stderr, "Error: Bad regex.  Try again with something else!\n");
      break;
    }

    case X_SIG_INTERRUPT: {
      fprintf(stderr, "\nCaught SIGINT after %llu tries - exiting.\n", ++loop);
      break;
    }

    case X_YOURE_UNLUCKY: {
      fprintf(stderr, "\nError: You happened to find a bad key - congrats.\n");
      break;
    }

    case X_KEY_GEN_FAILS: {
      fprintf(stderr, "Error: RSA Key Generation failed.  This is bad.\n");
      break;
    }

    case X_THREAD_CREATE: {
      fprintf(stderr, "Error: Failed to create thread.  Terminating...\n");
      break;
    }

#ifdef BSD
    case X_SYSCTLBN_FAIL: {
      fprintf(stderr, "Error: sysctlbyname failed.\n");
      break;
    }

#elif defined(LINUX_PORT)
    case X_BAD_FILE_DESC: {
      fprintf(stderr, "Error: Couldn't open processor information.\n");
      break;
    }

    case X_ABNORMAL_READ: {
      fprintf(stderr, "Error when reading processor information.\n");
      break;
    }
#endif

    default: {
      fprintf(stderr, "Generic error.  You should never see this...\n");
      break;
    }
  }
  exit(code);
}

// Ctrl+C handler
void terminate(int signum) {
  error(X_SIG_INTERRUPT);
}

// LCM for BIGNUMs
int BN_lcm(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *gcd, BN_CTX *ctx) {
  BIGNUM *tmp = BN_CTX_get(ctx);
  if(!BN_div(tmp, NULL, a, gcd, ctx))
    return 0;
  if(!BN_mul(r, b, tmp, ctx))
    return 0;
  return 1;
}

// base32 encode hash
void base32_onion(char *dst, unsigned char *src) {
  uint16_t i, bit, v, u;
  for(i = 0, bit = 0; bit < BASE32_NUM_BITS; ++i, bit += 5) {
    v = ((uint8_t)src[bit/8]) << 8;
    if(bit+5 < BASE32_NUM_BITS) v += (uint8_t)src[(bit/8)+1];
    u = (v >> (11-(bit%8))) & 0x1F;
    dst[i] = BASE32_ALPHABET[u];
  }
  dst[i] = '\0';
}

// pretty print hash
void print_onion(char *onion) {
  uint8_t i;
  char *s;
  asprintf(&s, "Found matching domain after %llu tries: %s.onion", loop, onion);
  for(i=0; i<strlen(s); i++)
    printf("-");
  printf("\n%s\n", s);
  for(i=0; i<strlen(s); i++)
    printf("-");
  printf("\n");
}

// print PEM formated RSA key
void print_prkey(RSA *rsa) {
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

// checks sanity of a RSA key (PKCS#1 v2.1)
uint8_t sane_key(RSA *rsa) {
  uint8_t sane = 1;

  BN_CTX *ctx = BN_CTX_new();
  BN_CTX_start(ctx);
  BIGNUM *p1     = BN_CTX_get(ctx), // p - 1
         *q1     = BN_CTX_get(ctx), // q - 1
         *chk    = BN_CTX_get(ctx), // storage to run checks with
         *gcd    = BN_CTX_get(ctx), // GCD(p - 1, q - 1)
         *lambda = BN_CTX_get(ctx); // LCM(p - 1, q - 1)

  // p - 1, q - 1, and lambda(n) calculation
  BN_sub(p1, rsa->p, BN_value_one());
  BN_sub(q1, rsa->q, BN_value_one());
  BN_gcd(gcd, p1, q1, ctx);
  BN_lcm(lambda, p1, q1, gcd, ctx);

  // check if public exponent e is coprime to lambda(n)
  BN_gcd(chk, lambda, rsa->e, ctx);
  if(!BN_is_one(chk))
    sane = 0;

  // check if public exponent e is less than n - 1
  // subtract n from e to avoid having to check BN_is_zero
  BN_sub(chk, rsa->e, rsa->n);
  if(!chk->neg)
    sane = 0;

  // d, dmp1, dmq1 and iqmp are calculated
  BN_mod_inverse(rsa->d, rsa->e, lambda, ctx);
  BN_mod(rsa->dmp1, rsa->d, p1, ctx);
  BN_mod(rsa->dmq1, rsa->d, q1, ctx);
  BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  // this is excessive but you're better off safe than (very) sorry
  // in theory this should never be true unless I made a mistake ;)
  if(RSA_check_key(rsa) != 1)
    sane = 0;

  return sane;
}

// thread proc - we spawn one for each processor on the system
void *worker(void *unused) {
  uint16_t len;
  unsigned char buf[SHA1_DIGEST_LEN],
                pem[RSA_KEYS_BITLEN],
                *tmp;
  char onion[BASE32_ONIONLEN];
  SHA_CTX hash;

  // only the first key is generated by OpenSSL
  RSA *rsa = RSA_generate_key(RSA_KEYS_BITLEN, RSA_PK_EXPONENT, NULL, NULL);
  if(!rsa) // if key generation fails (no prng seed?)
    error(X_KEY_GEN_FAILS);

  while(!found) { // main loop
    // calculate next RSA private key
    BN_add_word(rsa->e, 2L);
    // convert RSA key to PEM format
    tmp = &pem[0];
    len = i2d_RSAPublicKey(rsa, &tmp);
    pem[len] = '\0';
    // compute SHA1 digest of PEM-formated RSA key
    SHA1_Init(&hash);
    SHA1_Update(&hash, pem, len);
    SHA1_Final(buf, &hash);
    // base32 encode SHA1 digest
    base32_onion(onion, buf);
    loop++;
    if(!regexec(regex, onion, 0, 0, 0)) { // check for a match
      // let our main thread know who to wait on
      lucky_thread = pthread_self();
      found = 1; // kill off our other threads, asyncronously

      // check that we have a good key
      if(!sane_key(rsa))
        error(X_YOURE_UNLUCKY); // bad key :(

      // print results
      print_onion(onion);
      print_prkey(rsa);
      RSA_free(rsa);
      return 0;
    }
  }
  // let our other threads free their (now useless) stuff
  RSA_free(rsa);
  return 0;
}

#ifdef LINUX_PORT
// Linux specific stuff (damn this is ugly code.  blame linus.)
int8_t parse_cpuinfo(char *buf, uint16_t avail, int16_t *used) {
  uint16_t x = 0;
  char procsfound = 0;
  static uint8_t skip = 0;
//  static const magic_string = CPUINFO_PROCESSOR_STRING;

  if(!skip) {
    if(memcmp(&CPUINFO_PROC_STR, buf, CPUINFO_PROC_STR_LEN) == 0)
      procsfound++;
  }

  while((buf[x] != 0) && (x < avail)) {
    if(x) {
      if(buf[x - 1] == '\n') {
        break;
      }
    }
    x++;
  }

  *used = x;

  if(!x)
    return 0; // prevent the next if statement from causing a buffer overflow

  if((x == avail) && (buf[x - 1] != '\n'))
    skip = 1;
  else
    skip = 0;

  return procsfound;
}
#endif

// onions are fun, here we go (please remember to fasten your seatbelts...)
int main(int argc, char *argv[]) {
  // set signal handler to terminate() on CTRL-C
  signal(SIGINT, terminate);

  if(argc != 2) // not enough or too many arguments
    usage();

  //  compile regular expression from argument
  char *pattern = argv[1];
  regex = malloc(REGEX_COMP_LMAX);
  if(regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB))
    error(X_REGEX_COMPILE);

  uint32_t threads = 0, x;

  #ifdef BSD // yay for BSD!
  size_t size = sizeof(threads);
  if(sysctlbyname(SYSCTL_ID_CPUS, &threads, &size, NULL, 0))
    error(X_SYSCTLBN_FAIL);

  #elif defined(LINUX_PORT) // Oh no!  We're on linux... :(
  // ...even *Windows 95* (gasp!) has a better way of doing this...
  char cpuinfo[CPUINFO_BUF_SIZE] = "";
  int fd = open(CPUINFO_PATH, O_RDONLY);

  if(fd < 0)
    error(X_BAD_FILE_DESC);

  size_t r = 0;
  ssize_t tmp;
  short used = 0;

  do {
    // fill the buffer with goodies
    tmp = read(fd, &cpuinfo[r], CPUINFO_BUF_SIZE - r);

    if(tmp < 0)
      error(X_ABNORMAL_READ);

    r += tmp;
    if(r < CPUINFO_BUF_SIZE)
      cpuinfo[r] = 0;
    threads += parse_cpuinfo(&cpuinfo[0], (uint16_t)r, &used);
    r -= used;
    memmove(&cpuinfo[0], &cpuinfo[used], r);
  } while(used > 0);
  close(fd); // TODO: add error handling!
  #endif // we catch both BSD and LINUX_PORT being undef earlier

  pthread_t thrd;

  // create our threads for 2+ cores
  for(x = 1; x < threads; x++) {
    if(pthread_create(&thrd, NULL, worker, NULL))
      error(X_THREAD_CREATE);
  }

  // use main thread for brute forcing too
  worker(NULL);

  if(pthread_self() != lucky_thread) // be safe and avoid EDEADLK
    pthread_join(lucky_thread, NULL); // wait for the lucky thread to exit

  regfree(regex);
  return 0;
}
