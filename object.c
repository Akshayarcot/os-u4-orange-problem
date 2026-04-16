#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "object.h"

/* Convert enum to string */
const char *type_to_string(enum object_type type) {
    switch (type) {
        case OBJ_BLOB: return "blob";
        case OBJ_TREE: return "tree";
        case OBJ_COMMIT: return "commit";
        default: return "blob";
    }
}

/* Convert hash to hex */
void hash_to_hex(const unsigned char *hash, char *hex) {
    for (int i = 0; i < 32; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
}

int object_write(enum object_type type, const void *data, size_t size, char *out_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    const char *type_str = type_to_string(type);

    // header
    char header[64];
    int header_len = sprintf(header, "%s %zu", type_str, size) + 1;

    size_t total_size = header_len + size;
    unsigned char *full = malloc(total_size);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, size);

    // hash
    SHA256(full, total_size, hash);
    hash_to_hex(hash, out_hash);

    // directories
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", out_hash);
    mkdir(dir, 0755);

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, out_hash + 2);

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

int object_read(const char *hash, enum object_type *type, void **data, size_t *size) {
    char path[512];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

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

    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    char type_str[10];
    sscanf((char *)buffer, "%s %zu", type_str, size);

    if (strcmp(type_str, "blob") == 0) *type = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type = OBJ_COMMIT;

    size_t header_len = (null_pos - (char *)buffer) + 1;

    *data = malloc(*size);
    if (!(*data)) {
        free(buffer);
        return -1;
    }

    memcpy(*data, buffer + header_len, *size);

    free(buffer);
    return 0;
}
