#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/sha.h>

/* Convert enum to string */
const char *type_to_string(ObjectType type) {
    switch (type) {
        case OBJ_BLOB: return "blob";
        case OBJ_TREE: return "tree";
        case OBJ_COMMIT: return "commit";
        default: return "blob";
    }
}

/* ========================= */
/* WRITE OBJECT */
/* ========================= */
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    const char *type_str = type_to_string(type);

    // 1. Create header
    char header[64];
    int header_len = sprintf(header, "%s %zu", type_str, len) + 1;

    size_t total_size = header_len + len;

    unsigned char *full = malloc(total_size);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // 2. Compute SHA256 → store in ObjectID
    SHA256(full, total_size, id_out->hash);

    // 3. Convert to hex
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    // 4. Create directories safely
    if (mkdir(".pes", 0755) != 0 && errno != EEXIST) {
        free(full);
        return -1;
    }

    if (mkdir(".pes/objects", 0755) != 0 && errno != EEXIST) {
        free(full);
        return -1;
    }

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", hex);

    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        free(full);
        return -1;
    }

    // 5. File path
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, hex + 2);

    // 6. Write object
    FILE *f = fopen(path, "wb");
    if (!f) {
        free(full);
        return -1;
    }

    if (fwrite(full, 1, total_size, f) != total_size) {
        fclose(f);
        free(full);
        return -1;
    }

    fclose(f);
    free(full);
    return 0;
}

/* ========================= */
/* READ OBJECT */
/* ========================= */
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);

    char path[512];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hex, hex + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // read file
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

    // 1. Integrity check
    unsigned char verify[SHA256_DIGEST_LENGTH];
    SHA256(buffer, file_size, verify);

    if (memcmp(verify, id->hash, SHA256_DIGEST_LENGTH) != 0) {
        free(buffer);
        return -1;
    }

    // 2. Parse header
    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    char type_str[10];
    sscanf((char *)buffer, "%s %zu", type_str, len_out);

    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    // 3. Extract data
    size_t header_len = (null_pos - (char *)buffer) + 1;

    *data_out = malloc(*len_out);
    if (!(*data_out)) {
        free(buffer);
        return -1;
    }

    memcpy(*data_out, buffer + header_len, *len_out);

    free(buffer);
    return 0;
}
