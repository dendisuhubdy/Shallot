// thread procs for shallot

#include "config.h"

#include <stdint.h> // OpenBSD needs this included before sys/endian.h

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)
  #include "linux.h"
#else
  #include <sys/param.h> // OpenBSD needs this early on too
  #include <sys/endian.h>
#endif

#include "math.h"
#include "print.h"
#include "error.h"
#include "thread.h"
#include "defines.h"
#include "globals.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

void *worker(void *unused) { // life cycle of a cracking pthread
  uint16_t len;
  uint64_t e_be; // storage for our "big endian" version of e
  uint8_t buf[SHA1_DIGEST_LEN],
          der[RSA_KEYS_BITLEN];
  char onion[BASE32_ONIONLEN];
  SHA_CTX hash, copy;
  RSA *rsa = 0;

  if(verbose)
    printf("Thread entering loop... (ID: 0x%X)\n", (uint32_t)pthread_self());

  while(!found) {
    // keys are only generated every so often
    // every 549,755,781,120 tries by default
    if(verbose)
      printf("Generating new key... (ID: 0x%X)\n", (uint32_t)pthread_self());

    rsa = RSA_generate_key(RSA_KEYS_BITLEN, RSA_PK_EXPONENT, NULL, NULL);
    if(!rsa) // if key generation fails (no prng seed?)
      error(X_KEY_GEN_FAILS);

    uint8_t *tmp = der;
    len = i2d_RSAPublicKey(rsa, &tmp); // convert RSA key to X.690 DER format
    if(len != RSA_EXP_DER_LEN) // if we got an unexpected length...
      continue; // ...try again

    uint8_t e_bytes = RSA_PK_E_LENGTH; // number of bytes e occupies
    uint64_t e = RSA_PK_EXPONENT; // public exponent
    uint64_t e_byte_thresh;

    SHA1_Init(&hash); // TODO: move to a function (is that thread safe?)
    SHA1_Update(&hash, der, RSA_REL_DER_LEN);

    int_pow(2, e_bytes * 8, &e_byte_thresh);
    e_byte_thresh++;

    uint8_t *e_ptr = ((uint8_t*)&e_be) + 8 - e_bytes;

    while((e <= elim) && !found) { // main loop
      // copy the relevant parts of our already set up context
      memcpy(&copy, &hash, SHA_REL_CTX_LEN); // 40 bytes here...
      copy.num = hash.num;                   // and don't forget the num (9)

      // convert e to big-endian format
      e_be = htobe64(e);

      // compute SHA1 digest (majority of loop time spent here?  time it!)
      SHA1_Update(&copy, e_ptr, e_bytes);
      SHA1_Final(buf, &copy);

      base32_onion(onion, buf); // base32 encode SHA1 digest
      loop++; // keep track of our tries...

      if(!regexec(regex, onion, 0, 0, 0)) { // check for a match
        if(verbose)
          printf("Matching hash found, killing off other threads..."
                 " (ID: 0x%X)\n", (uint32_t)pthread_self());

        // let our main thread know on which thread to wait
        lucky_thread = pthread_self();
        found = 1; // kill off our other threads, asyncronously

        if(monitor)
          printf("\n"); // keep our printing pretty!

        if(!BN_bin2bn(e_ptr, e_bytes, rsa->e)) // store our e in the actual key
          error(X_BIGNUM_FAILED); // and make sure it got there

        if(!sane_key(rsa)) // check our key
          error(X_YOURE_UNLUCKY); // bad key :(

        if(verbose)
          printf("Public exponent (e) is 0x%llX.\n", e);

        print_onion(onion); // print our domain
        print_prkey(rsa); // and more importantly the key

        RSA_free(rsa); // free up what's left

        if(verbose)
          printf("Thread exiting loop... (ID: 0x%X)\n",
                 (uint32_t)pthread_self());

        return 0;
      }

      e += 2; // do *** NOT *** forget this!

      if(e == e_byte_thresh) { // ASN.1 stuff (hey, it could be worse!)
        // calculate our new threshold
        int_pow(2, ++e_bytes * 8, &e_byte_thresh);
        e_byte_thresh++;

        // play with our key structure (do not try this at home!)
        der[RSA_ADD_DER_OFF]++;
        der[RSA_REL_DER_LEN - 1]++;

        // and our prebuilt hash
        SHA1_Init(&hash); // TODO: move to a function (is that thread safe?)
        SHA1_Update(&hash, der, RSA_REL_DER_LEN);

        e_ptr--; // and move the pointer back
      }
    }
  }

  if(rsa) // let our other threads free their (now useless) stuff
    RSA_free(rsa);

  if(verbose)
    printf("Thread exiting loop... (ID: 0x%X)\n", (uint32_t)pthread_self());

  return 0;
}

void *monitor_proc(void *unused) {
  printf("\033[sPlease wait a moment for statistics...");
  time_t start = time(NULL);

  for(;;) {
    fflush(stdout); // make sure it gets printed
    sleep(20);

    if(found)
      return 0;

    time_t current = time(NULL);
    time_t elapsed = current - start;

    if(!elapsed)
      continue; // be paranoid and avoid divide-by-zero exceptions

    printf("\033[u\033[KHashes: %-20llu  Time: %-10d  Speed: %-llu",
           loop, (int)elapsed, loop / elapsed);
  }

  return 0; // unreachable code, but prevents warnings (!?)
}

