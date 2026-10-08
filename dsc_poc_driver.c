/*
 * dsc_poc_driver.c — DSC-EXTRACTOR-TRAVERSAL-1 PoC driver
 *
 * Implements the EXACT vulnerable code path from dsc_extractor.cpp:
 *   SharedCacheDylibExtractor::extractCache()
 *   make_dirs()
 *
 * The vulnerable pattern:
 *   char dylib_path[PATH_MAX];
 *   strcpy(dylib_path, extraction_root_path);
 *   strcat(dylib_path, "/");
 *   strcat(dylib_path, name);   // 'name' = attacker pathFileOffset, no .. check
 *   make_dirs(dylib_path);
 *   int fd = open(dylib_path, O_CREAT|O_TRUNC|O_RDWR, 0644);
 *
 * Usage:
 *   ./dsc_poc_driver <cache_file> <outdir>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <errno.h>

/* ── dyld shared cache structs (from dyld_cache_format.h) ─────────────────── */
typedef struct {
    char     magic[16];
    uint32_t mappingOffset;
    uint32_t mappingCount;
    uint32_t imagesOffsetOld;
    uint32_t imagesCountOld;
    uint64_t dyldBaseAddress;
    uint64_t codeSignatureOffset;
    uint64_t codeSignatureSize;
    /* ... many fields ... */
    /* offset 232: */ uint64_t _pad0[24];  /* dyldBaseAddress(8)+csOff(8)+csSz(8) = 24 bytes from off 32 → off 56; then more fields */
} dyld_cache_header_raw;

typedef struct {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;
    uint32_t maxProt;
    uint32_t initProt;
} dyld_cache_mapping_info;

typedef struct {
    uint64_t address;
    uint64_t modTime;
    uint64_t inode;
    uint32_t pathFileOffset;
    uint32_t pad;
} dyld_cache_image_info;

/* ── Minimal header field accessors by raw byte offset ───────────────────── */
static uint32_t hdr_u32(const uint8_t *base, size_t off) {
    uint32_t v; memcpy(&v, base + off, 4); return v;
}
static uint64_t hdr_u64(const uint8_t *base, size_t off) {
    uint64_t v; memcpy(&v, base + off, 8); return v;
}

/* ── make_dirs: identical logic to dsc_extractor.cpp make_dirs() ─────────── */
static void make_dirs(const char *path) {
    char tmp[PATH_MAX];
    strlcpy(tmp, path, sizeof(tmp));
    /* walk backwards to find last '/' then create each component */
    char *p = strrchr(tmp, '/');
    if (!p) return;
    *p = '\0';
    /* mkdir -p */
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <cache_file> <outdir>\n", argv[0]);
        return 1;
    }
    const char *cache_path = argv[1];
    const char *outdir     = argv[2];

    /* ── 1. Map the cache file ─────────────────────────────────────────── */
    int fd = open(cache_path, O_RDONLY);
    if (fd < 0) { perror("open cache"); return 1; }
    off_t file_size = lseek(fd, 0, SEEK_END);
    const uint8_t *base = mmap(NULL, (size_t)file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }

    /* ── 2. Validate magic ─────────────────────────────────────────────── */
    if (memcmp(base, "dyld_v1", 7) != 0) {
        fprintf(stderr, "Bad magic\n"); return 1;
    }
    printf("[*] Cache magic: %.16s\n", base);

    /* ── 3. Read header fields (exact byte offsets from dyld_cache_format.h) */
    uint32_t mappingOffset = hdr_u32(base, 16);
    uint32_t mappingCount  = hdr_u32(base, 20);
    uint64_t sharedRegSize = hdr_u64(base, 232);
    uint32_t imagesOffset  = hdr_u32(base, 448);
    uint32_t imagesCount   = hdr_u32(base, 452);

    printf("[*] mappingOffset=0x%x mappingCount=%u\n", mappingOffset, mappingCount);
    printf("[*] sharedRegionSize=0x%llx\n", (unsigned long long)sharedRegSize);
    printf("[*] imagesOffset=0x%x imagesCount=%u\n", imagesOffset, imagesCount);

    if (mappingCount == 0) { fprintf(stderr, "No mappings\n"); return 1; }
    if (sharedRegSize == 0) { fprintf(stderr, "sharedRegionSize=0, abort\n"); return 1; }

    /* ── 4. forEachImage() gate: mappings[0].fileOffset must be 0 ──────── */
    const dyld_cache_mapping_info *mappings =
        (const dyld_cache_mapping_info *)(base + mappingOffset);
    if (mappings[0].fileOffset != 0) {
        fprintf(stderr, "mappings[0].fileOffset != 0, abort\n"); return 1;
    }
    uint64_t firstRegionAddress = mappings[0].address;
    printf("[*] firstRegionAddress=0x%llx fileOffset=0 ✓\n",
           (unsigned long long)firstRegionAddress);

    /* ── 5. Iterate images — VULNERABLE CODE PATH ──────────────────────── */
    const dyld_cache_image_info *dylibs =
        (const dyld_cache_image_info *)(base + imagesOffset);

    printf("[*] Processing %u image(s)...\n", imagesCount);

    for (uint32_t i = 0; i < imagesCount; i++) {
        /* This is the attacker-controlled string — NO sanitization */
        const char *name = (const char *)(base + dylibs[i].pathFileOffset);
        printf("[*] Image[%u] installName = \"%s\"\n", i, name);

        /* ── VULNERABLE: strcat without .. sanitization ─────────────────
         *   char dylib_path[PATH_MAX];
         *   strcpy(dylib_path, extraction_root_path);
         *   strcat(dylib_path, "/");
         *   strcat(dylib_path, name);          ← BUG IS HERE
         */
        char dylib_path[PATH_MAX];
        strcpy(dylib_path, outdir);
        strcat(dylib_path, "/");
        strcat(dylib_path, name);   /* ← CWE-22: no .. check */

        printf("[*] Resolved path: \"%s\"\n", dylib_path);

        /* make_dirs creates parent directories (including traversal dirs) */
        make_dirs(dylib_path);

        /* Create the file at the (possibly traversed) path */
        int out_fd = open(dylib_path, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (out_fd < 0) {
            fprintf(stderr, "[-] open(%s): %s\n", dylib_path, strerror(errno));
        } else {
            /* Write a marker so the file is non-empty */
            const char marker[] = "DSC-EXTRACTOR-TRAVERSAL-1 PoC\n";
            write(out_fd, marker, sizeof(marker) - 1);
            close(out_fd);
            printf("[+] File created: \"%s\"\n", dylib_path);
        }
    }

    munmap((void *)base, (size_t)file_size);
    return 0;
}
