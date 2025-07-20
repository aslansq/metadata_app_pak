#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>

uint32_t crc_cal32(const uint8_t *ptr, uint32_t len, uint32_t start_val);

#endif // CRC32_H