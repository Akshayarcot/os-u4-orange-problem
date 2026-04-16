#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "object.h"

/*
 * Helper: convert binary hash → hex string
 */
void hash_to_hex(const unsigned char *hash, char *hex) {
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
}

/*
 * Write object to .pes/objects
 */
int object_write(const char *type, const void *data, size_t size, char *out_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // 1. Create header: "type size\0"
    char header[64];
    int header_len = sprintf(header, "%s %zu", type, size) + 1;

    // 2. Combine header + data
    size_t total_size = header_len + size;
    unsigned char *full = malloc(total_size);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, size);

    // 3. Compute SHA256
    SHA256(full, total_size, hash);

    // 4. Convert to hex
    hash_to_hex(hash, out_hash);

    // 5. Create directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", out_hash);
    mkdir(dir, 0755);

    // 6. File path
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, out_hash + 2);

    // 7. Write file
    FILE *f = fopen(path, "wb");
    if (!f) {
        free(full);
        return -1;
    }

    fwrite(full, 1, total_size, f);
    fclose(f);

    free(full);
    return 0;
}

/*
 * Read object from .pes/objects
 */
int object_read(const char *hash, char *type, void **data, size_t *size) {
    char path[512];

    // 1. Build file path
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 2. Get file size
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(f);
        return -1;
    }

    fread(buffer, 1, file_size, f);
    fclose(f);

    // 3. Parse header
    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    // Extract type and size
    sscanf((char *)buffer, "%s %zu", type, size);

    // 4. Extract data
    size_t header_len = (null_pos - (char *)buffer) + 1;
    *data = malloc(*size);
    if (!(*data)) {
        free(buffer);
        return -1;
    }

    memcpy(*data, buffer + header_len, *size);

    // 5. Verify hash (optional but good)
    unsigned char verify_hash[SHA256_DIGEST_LENGTH];
    SHA256(buffer, file_size, verify_hash);

    char verify_hex[65];
    hash_to_hex(verify_hash, verify_hex);

    if (strcmp(verify_hex, hash) != 0) {
        free(buffer);
        free(*data);
        return -1;
    }

    free(buffer);
    return 0;
}
