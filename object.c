#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
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
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex + (i * 2), "%02x", hash[i]);
    }
    hex[64] = '\0';
}

/* ========================= */
/* WRITE OBJECT (FIXED) */
/* ========================= */
int object_write(enum object_type type, const void *data, size_t size, char *out_hash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    const char *type_str = type_to_string(type);

    /* 1. Create header */
    char header[64];
    int header_len = sprintf(header, "%s %zu", type_str, size) + 1;

    /* 2. Combine header + data */
    size_t total_size = header_len + size;
    unsigned char *full = malloc(total_size);
    if (!full) return -1;

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, size);

    /* 3. Compute SHA256 */
    SHA256(full, total_size, hash);
    hash_to_hex(hash, out_hash);

    /* 4. Create directories */
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);

    char dir[256];
    snprintf(dir, sizeof(dir), ".pes/objects/%.2s", out_hash);
    mkdir(dir, 0755);

    /* 5. Final path */
    char final_path[512];
    snprintf(final_path, sizeof(final_path), "%s/%s", dir, out_hash + 2);

    /* 6. TEMP FILE (atomic write) */
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tempXXXXXX", dir);

    int fd = mkstemp(temp_path);
    if (fd == -1) {
        free(full);
        return -1;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        close(fd);
        free(full);
        return -1;
    }

    if (fwrite(full, 1, total_size, f) != total_size) {
        fclose(f);
        free(full);
        return -1;
    }

    fflush(f);
    fclose(f);

    /* 7. Rename temp → final */
    if (rename(temp_path, final_path) != 0) {
        free(full);
        return -1;
    }

    free(full);
    return 0;
}

/* ========================= */
/* READ OBJECT */
/* ========================= */
int object_read(const char *hash, enum object_type *type, void **data, size_t *size) {
    char path[512];
    snprintf(path, sizeof(path), ".pes/objects/%.2s/%s", hash, hash + 2);

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    /* Read entire file */
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

    /* Find header end */
    char *null_pos = memchr(buffer, '\0', file_size);
    if (!null_pos) {
        free(buffer);
        return -1;
    }

    /* Parse header */
    char type_str[10];
    sscanf((char *)buffer, "%s %zu", type_str, size);

    if (strcmp(type_str, "blob") == 0) *type = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type = OBJ_COMMIT;
    else {
        free(buffer);
        return -1;
    }

    /* Extract data */
    size_t header_len = (null_pos - (char *)buffer) + 1;

    *data = malloc(*size);
    if (!(*data)) {
        free(buffer);
        return -1;
    }

    memcpy(*data, buffer + header_len, *size);

    /* Verify hash (IMPORTANT) */
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
