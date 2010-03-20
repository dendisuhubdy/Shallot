#ifndef LINUX_H
#define LINUX_H

#include "config.h"

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)
#include <stdint.h>
uint64_t htobe64(uint64_t x);
#endif

#ifdef LINUX_PORT
uint8_t parse_cpuinfo(char *buf, uint16_t avail, uint16_t *used);
#endif

#endif
