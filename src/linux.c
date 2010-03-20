// linux specific stuff for shallot

#include "linux.h"

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)

#include "defines.h"

#if defined(OSX) || defined(GENERIC)
#include <arpa/inet.h>
#else
#include <endian.h>
#include <netinet/in.h>
#endif

// why must glibc suck?
#if BYTE_ORDER == BIG_ENDIAN
#warning Compiling for a BIG_ENDIAN system.
#define htobe64(x) (x)
#elif BYTE_ORDER == LITTLE_ENDIAN
#warning Compiling for a LITTLE_ENDIAN system.
uint64_t htobe64(uint64_t x) {
  return ((uint64_t)htonl(x) << 32) | htonl(x >> 32);
}
#else
  #error Sell your PDP.
#endif
#endif // defined(LINUX_PORT) || defined(OSX)

#ifdef LINUX_PORT
#include <string.h>

// Linux specific stuff (damn this is ugly code.  blame linus.)
uint8_t parse_cpuinfo(char *buf, uint16_t avail, uint16_t *used) {
  uint16_t x = 0;
  char procsfound = 0;
  static uint8_t skip = 0;

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

