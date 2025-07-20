#ifndef PAK_H
#define PAK_H

#include <stdint.h>

typedef struct __attribute__((__packed__)) {
	uint8_t major;
	uint8_t minor;
	uint8_t patch;
	uint8_t reserved;
} pak_sw_ver_t;

typedef struct __attribute__((__packed__)) {
	uint32_t size; // size of the app in bytes
	pak_sw_ver_t version; // app software version
	uint64_t epoch_time; // app build time in seconds since epoch
	uint32_t fingerprint; // app builder fingerprint
	uint32_t offset; // offset of the app binary in the output file
	uint8_t md5_hash[16]; // MD5 hash of the app binary
	uint32_t crc; // CRC32 checksum of the this structure
} pak_app_info_t;

#endif // PAK_H