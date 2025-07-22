#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>

#include "pak.h"
#include "crc32.h"
#include "md5.h"

static uint64_t get_bin_size(char *file_path_ptr) {
	uint64_t file_size;
	FILE *file_ptr;
	file_ptr = fopen(file_path_ptr, "rb");
	if (file_ptr == NULL) {
		printf("Failed to open file %s\n", file_path_ptr);
		exit(1);
	}
	fseek(file_ptr, 0, SEEK_END);
	file_size = ftell(file_ptr);
	fclose(file_ptr);

	if(file_size % sizeof(uint32_t)) {
		printf("Input binary app_size should be divisible 4\n");
		exit(1);
	}

	return file_size;
}

static uint8_t *get_bin(char *file_path_ptr, uint64_t bin_size) {
	FILE *file_ptr;
	uint64_t bin_read;

	file_ptr = fopen(file_path_ptr, "rb");

	if (file_ptr == NULL) {
		printf("Failed to read file %s\n", file_path_ptr);
		exit(1);
	}

	uint8_t *buf_ptr = (uint8_t *)malloc(bin_size);

	if (buf_ptr == NULL) {
		printf("Failed to allocate memory\n");
		exit(1);
	}

	bin_read = fread(buf_ptr, sizeof(uint8_t), bin_size, file_ptr);

	if (bin_read != bin_size) {
		printf("Failed to read file\n");
		free(buf_ptr);
		exit(1);
	}
	return buf_ptr;
}

static void write_bin(char *file_path_ptr, uint8_t *buf_ptr, uint64_t bin_size) {
	FILE *file_ptr;
	file_ptr = fopen(file_path_ptr, "wb");

	if (file_ptr == NULL) {
		printf("Failed to write file %s\n", file_path_ptr);
		exit(1);
	}

	size_t bin_written = fwrite(buf_ptr, sizeof(uint8_t), bin_size, file_ptr);

	if (bin_written != bin_size) {
		printf("Failed to write file\n");
		fclose(file_ptr);
		exit(1);
	}

	fclose(file_ptr);
}

static void pak(
	char *in_file_path_ptr,
	int major,
	int minor,
	int patch,
	int fingerprint,
	int offset,
	char *out_file_path_ptr
)
{
	pak_app_metadata_t pak_app_metadata;
	MD5Context md5_ctx;
	memset(&md5_ctx, 0, sizeof(MD5Context));
	memset(&pak_app_metadata, 0, sizeof(pak_app_metadata_t));
	
	uint64_t bin_size = get_bin_size(in_file_path_ptr);

	pak_app_metadata.size = (uint32_t)bin_size;
	pak_app_metadata.version.major = (uint8_t)major;
	pak_app_metadata.version.minor = (uint8_t)minor;
	pak_app_metadata.version.patch = (uint8_t)patch;
	pak_app_metadata.version.reserved = 0;
	pak_app_metadata.epoch_time = (uint64_t)time(NULL);
	pak_app_metadata.fingerprint = (uint32_t)fingerprint;
	pak_app_metadata.offset = (uint32_t)offset;

	uint8_t *bin_ptr = get_bin(in_file_path_ptr, bin_size);
	
	if (bin_ptr == NULL) {
		printf("Failed to read binary file %s\n", in_file_path_ptr);
		exit(1);
	}

	md5Calc(&md5_ctx, bin_ptr, (uint32_t)bin_size);
	memcpy(pak_app_metadata.md5_hash, md5_ctx.digest, sizeof(pak_app_metadata.md5_hash));

	pak_app_metadata.crc = crc_cal32(
		(uint8_t *)&pak_app_metadata,
		sizeof(pak_app_metadata_t) - sizeof(pak_app_metadata.crc),
		UINT32_MAX
	);

	uint8_t *out_bin_ptr = (uint8_t *)malloc(offset + bin_size);

	if(out_bin_ptr == NULL) {
		printf("Failed to allocate memory for output buffer\n");
		exit(1);
	}

	uint32_t out_bin_size = offset + bin_size;
	memset(out_bin_ptr, 0xff, out_bin_size);

	memcpy(out_bin_ptr, &pak_app_metadata, sizeof(pak_app_metadata_t));
	memcpy(out_bin_ptr + offset, bin_ptr, bin_size);

	write_bin(out_file_path_ptr, out_bin_ptr, out_bin_size);

	if(out_bin_ptr != NULL) {
		free(out_bin_ptr);
	}

	if(bin_ptr != NULL) {
		free(bin_ptr);
	}
}

static void pak_check(char *out_file_path_ptr)
{
	uint64_t bin_size = get_bin_size(out_file_path_ptr);
	uint8_t *bin_ptr = get_bin(out_file_path_ptr, bin_size);

	if (bin_ptr == NULL) {
		printf("Failed to read binary file %s\n", out_file_path_ptr);
		exit(1);
	}

	pak_app_metadata_t *pak_app_metadata_ptr = (pak_app_metadata_t *)bin_ptr;
	uint8_t *app_bin_ptr = bin_ptr + pak_app_metadata_ptr->offset;

	uint32_t crc = crc_cal32(
		(uint8_t *)pak_app_metadata_ptr,
		sizeof(pak_app_metadata_t) - sizeof(pak_app_metadata_ptr->crc),
		UINT32_MAX
	);

	if (crc != pak_app_metadata_ptr->crc) {
		printf("CRC32 checksum mismatch: expected 0x%x, got 0x%x\n",
			pak_app_metadata_ptr->crc, crc);
		exit(1);
	} else {
		printf("CRC32 checksum is valid: 0x%x\n", crc);
	}

	MD5Context md5_ctx;
	memset(&md5_ctx, 0, sizeof(MD5Context));
	md5Calc(&md5_ctx, app_bin_ptr, pak_app_metadata_ptr->size);
	if (memcmp(md5_ctx.digest, pak_app_metadata_ptr->md5_hash, sizeof(pak_app_metadata_ptr->md5_hash)) != 0) {
		printf("MD5 hash mismatch: expected ");
		for (int i = 0; i < sizeof(pak_app_metadata_ptr->md5_hash); i++) {
			printf("%02x", pak_app_metadata_ptr->md5_hash[i]);
		}
		printf(", got ");
		for (int i = 0; i < sizeof(md5_ctx.digest); i++) {
			printf("%02x", md5_ctx.digest[i]);
		}
		printf("\n");
		exit(1);
	} else {
		printf("MD5 hash is valid: ");
		for (int i = 0; i < sizeof(pak_app_metadata_ptr->md5_hash); i++) {
			printf("%02x", pak_app_metadata_ptr->md5_hash[i]);
		}
		printf("\n");
	}

	printf("Application size: %u bytes\n", pak_app_metadata_ptr->size);
	printf("Application version: %u.%u.%u\n",
		pak_app_metadata_ptr->version.major,
		pak_app_metadata_ptr->version.minor,
		pak_app_metadata_ptr->version.patch);
	printf("Application build time: %lu seconds since epoch\n", pak_app_metadata_ptr->epoch_time);
	printf("Application fingerprint: %u\n", pak_app_metadata_ptr->fingerprint);
	printf("Application offset: %u bytes\n", pak_app_metadata_ptr->offset);
	
	if(bin_ptr != NULL) {
		free(bin_ptr);
	}
}

int main(int argc, char *argv[])
{
	int opt;
	int major = -1, minor = -1, patch = -1;
	int offset = -1;
	int fingerprint = 0;
	char *in_file_path_ptr = NULL;
	char *out_file_path_ptr = NULL;

	char help_str_arr[] =
		"Options:\n"
		"  -h   Show this help message\n"
		"  -i   Input file path                  (required)\n"
		"  -o   Output file path                 (required)\n"
		"  -m   Major version number             (required)\n"
		"  -n   Minor version number             (required)\n"
		"  -p   Patch version number             (required)\n"
		"  -t   Offset of the application binary (required)\n"
		"  -f   Fingerprint of the app builder   (optional, default is 0)\n";

	while((opt = getopt(argc, argv, "o:i:m:n:p:f:t:h")) != -1) {
		switch (opt) {
			case 'i':
				if (access(optarg, F_OK) == -1) {
					printf("Input file does not exist %s\n", optarg);
					exit(1);
				}
				int file_path_len = strlen(optarg);
				in_file_path_ptr = malloc(file_path_len + 1);
				if (in_file_path_ptr == NULL) {
					printf("Memory allocation failed for input file path.\n");
					exit(1);
				}
				strcpy(in_file_path_ptr, optarg);
				break;
			case 'o':
				char *last_slash_ptr = strrchr(optarg, '/');

				if (last_slash_ptr != NULL) {
					size_t dir_len = last_slash_ptr - optarg + 1;
					char *out_dir_ptr = malloc(dir_len + 1);
					if (out_dir_ptr == NULL) {
						printf("Memory allocation failed for output directory path.\n");
						exit(1);
					}

					strcpy(out_dir_ptr, optarg);

					if (access(out_dir_ptr, F_OK) == -1) {
						printf("Output directory does not exist %s\n", out_dir_ptr);
						free(out_dir_ptr);
						exit(1);
					}
					free(out_dir_ptr);
				}

				int out_file_path_len = strlen(optarg);
				out_file_path_ptr = malloc(out_file_path_len + 1);
				if (out_file_path_ptr == NULL) {
					printf("Memory allocation failed for output file path.\n");
					exit(1);
				}
				strcpy(out_file_path_ptr, optarg);
				
				break;
			case 'm':
				major = atoi(optarg);
				break;
			case 'n':
				minor = atoi(optarg);
				break;
			case 'p':
				patch = atoi(optarg);
				break;
			case 'h':
				printf("%s", help_str_arr);
				exit(0);
				break;
			case 'f':
				fingerprint = atoi(optarg);
				break;
			case 't':
				offset = atoi(optarg);
				break;
			default:
				printf("%s", help_str_arr);
				exit(1);
				break;
		}
	}

	if(major < 0 || major > UINT8_MAX) {
		printf("Invalid major version number. It must be between 0 and %d.\n", UINT8_MAX);
		exit(1);
	}
	if(minor < 0 || minor > UINT8_MAX) {
		printf("Invalid minor version number. It must be between 0 and %d.\n", UINT8_MAX);
		exit(1);
	}
	if(patch < 0 || patch > UINT8_MAX) {
		printf("Invalid patch version number. It must be between 0 and %d.\n", UINT8_MAX);
		exit(1);
	}
	if(in_file_path_ptr == NULL) {
		printf("Input file path is required.\n");
		exit(1);
	}
	if(out_file_path_ptr == NULL) {
		printf("Output file path is required.\n");
		exit(1);
	}
	if(fingerprint < 0 || fingerprint > UINT32_MAX) {
		printf("Invalid fingerprint. It must be a non-negative integer.\n");
		exit(1);
	}
	if(offset <= 0) {
		printf("Offset of the application binary must be a positive integer.\n");
		exit(1);
	}
	if(offset < sizeof(pak_app_metadata_t)) {
		printf("Offset must be bigger than %zu[sizeof(pak_app_metadata_t)] bytes.\n", sizeof(pak_app_metadata_t));
		exit(1);
	}

	pak(
		in_file_path_ptr,
		major,
		minor,
		patch,
		fingerprint,
		offset,
		out_file_path_ptr
	);

	pak_check(out_file_path_ptr);

	if (in_file_path_ptr != NULL) {
		free(in_file_path_ptr);
	}

	if(out_file_path_ptr != NULL) {
		free(out_file_path_ptr);
	}

	return 0;
}