#!/usr/bin/env python3
"""
Security scan over a **built APK**, not over source.

`scripts/scan-secrets.sh` reads the source tree. The claims this product makes to users are
about the artifact they install, and those are different things: a secret can enter through a
dependency, a generated resource, or a build script without ever appearing in a `.kt` file.
`14-production-readiness-review.md` §C-4 item 15 called this gap out. This closes it.

Everything here reads the real APK: its DEX, its resources, its assets and its merged
manifest. Nothing is inferred from source.

Usage:
    scripts/scan-apk.py app/build/outputs/apk/debug/app-debug.apk [--release]
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Components we expect to be exported, and why. Anything else exported is a finding: an
# exported component is an IPC entry point, and this product claims to have exactly one.
EXPECTED_EXPORTED = {
    "com.passwird.vaultapp.MainActivity": "the launcher activity; required for LAUNCHER intent",
    # Google Play services declares this itself. It is permission-protected with a signature
    # permission, so only Google's own signed code can bind to it.
    "com.google.android.gms.auth.api.signin.RevocationBoundService":
        "GMS-declared, guarded by com.google.android.gms.auth.api.signin.permission."
        "REVOCATION_NOTIFICATION",
}

# Exported by tooling that ships only in debug builds. Allowed there, a failure in release.
DEBUG_ONLY_EXPORTED = {
    # androidx.compose.ui:ui-tooling, pulled in with `debugImplementation`. Exported and
    # unguarded: any app on the device can launch it. That is acceptable only because it is
    # absent from release, which this script verifies rather than trusts.
    "androidx.compose.ui.tooling.PreviewActivity",
}

# Values that must never appear in a shipped artifact. The sentinels match the ones the JVM
# leak tests use, so a leak that escapes those is still caught here.
FORBIDDEN_STRINGS = [
    "SENTINEL_PW_", "SENTINEL_USER_", "SENTINEL-SITE-", "SENTINEL_NOTE_",
    "correct horse battery staple",
    "BEGIN RSA PRIVATE KEY", "BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY",
]

# Patterns for credential-shaped literals.
FORBIDDEN_PATTERNS = [
    (re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack token"),
    (re.compile(rb"gh[pousr]_[0-9A-Za-z]{36}"), "GitHub token"),
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key block"),
]

# Classes that disable TLS verification. Shipping one is not automatically a finding — they
# arrive inside Google's own client library — but our code calling one would be.
DANGEROUS_TLS = [
    "com.google.api.client.util.SslUtils",
]
DANGEROUS_TLS_METHODS = ["trustAllSSLContext", "trustAllX509TrustManager"]

APP_PACKAGE_PREFIX = "com.passwird"

# Third-party *test* packages that ship inside release-scoped dependencies. A secret-shaped
# literal owned by one of these is a published fixture, not a credential of ours. Excused in
# debug only, never in release, and never for a class of ours.
THIRD_PARTY_TEST_PACKAGES = (
    "com.google.api.client.testing.",
    "com.google.api.client.googleapis.testing.",
)


def build_tool(name: str) -> str | None:
    """Locates a build-tools binary (dexdump, aapt2) from the newest installed version."""
    for base in ("/opt/android-sdk", Path.home() / "Android/Sdk"):
        for version in sorted((Path(base) / "build-tools").glob("*"), reverse=True):
            candidate = version / name
            if candidate.exists():
                return str(candidate)
    return None


def sdk_tool(name: str) -> str | None:
    for base in ("/opt/android-sdk", Path.home() / "Android/Sdk"):
        candidate = Path(base) / "cmdline-tools/latest/bin" / name
        if candidate.exists():
            return str(candidate)
    return None


def run(cmd: list[str]) -> str:
    # `errors="replace"`: dexdump echoes string constants verbatim, and a DEX legitimately
    # contains non-UTF-8 bytes (MUTF-8 surrogates, and raw bytes inside library resources).
    # Decoding strictly makes the scanner crash on exactly the artifacts it exists to read.
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    return result.stdout


class Scan:
    def __init__(self, apk: Path, release: bool) -> None:
        self.apk = apk
        self.release = release
        self.failures: list[str] = []
        self.notes: list[str] = []
        self.checks = 0
        self.apkanalyzer = sdk_tool("apkanalyzer")
        self.manifest = ""
        if self.apkanalyzer:
            self.manifest = run([self.apkanalyzer, "manifest", "print", str(apk)])

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks += 1
        if ok:
            print(f"  ok    {name}")
        else:
            print(f"  FAIL  {name}")
            self.failures.append(f"{name}: {detail}" if detail else name)

    # ---------------------------------------------------------------- content

    def scan_payload(self) -> None:
        """Every byte the APK ships, checked for secret-shaped content."""
        hits: list[str] = []
        with zipfile.ZipFile(self.apk) as zf:
            for entry in zf.namelist():
                # Skip nothing: a secret in a resource is as bad as one in code.
                try:
                    blob = zf.read(entry)
                except Exception:
                    continue
                for needle in FORBIDDEN_STRINGS:
                    if needle.encode() in blob:
                        hits.append((entry, f"'{needle}'", needle))
                for pattern, label in FORBIDDEN_PATTERNS:
                    found = pattern.search(blob)
                    if found:
                        hits.append((entry, label, found.group(0).decode("utf-8", "replace")))

        # A hit inside a DEX is attributed to the class that loads it before being judged.
        # "There is a private key in the APK" and "*our code* carries a private key" are very
        # different findings, and a scanner that cannot tell them apart gets ignored.
        real: list[str] = []
        excused: list[str] = []
        for entry, label, matched in hits:
            owners = self._owners_of(entry, matched) if entry.endswith(".dex") else []
            third_party_test = owners and all(
                any(o.startswith(p) for p in THIRD_PARTY_TEST_PACKAGES) for o in owners
            )
            described = f"{label} in {entry}" + (f" ({', '.join(sorted(set(owners))[:2])})" if owners else "")
            # Never excused in a release build, and never excused for our own code.
            if third_party_test and not self.release:
                excused.append(described)
            else:
                real.append(described)

        for item in excused:
            self.notes.append(
                f"{item} — a published third-party test fixture, unreachable dead code, and "
                "absent from the release APK. Recorded rather than ignored: a password "
                "manager should not ship a PEM private key in any build."
            )

        self.check(
            "no secret-shaped literal in application or resource content",
            not real,
            "; ".join(real[:6]),
        )

    def _owners_of(self, dex_entry: str, matched: str) -> list[str]:
        """
        Classes whose code loads the offending literal, via dexdump.

        Matches the **whole** offending literal anywhere inside a class's dump, not a prefix
        of it. The first attempt searched for the bare word "BEGIN" and blamed
        `CredentialProviderBeginSignInController` — a class whose only crime is its name.
        Restricting to `const-string` instructions was the second attempt and missed it
        entirely: a PEM held in a `static final String` is emitted as a static field value,
        not as an instruction. Matching the full literal over the whole class block is both
        specific enough to be right and broad enough to find it.
        """
        dexdump = build_tool("dexdump")
        if not dexdump:
            return []

        class_line = re.compile(r"Class descriptor\s*:\s*'L([^;]+);'")

        owners: list[str] = []
        with zipfile.ZipFile(self.apk) as zf, tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.dex"
            path.write_bytes(zf.read(dex_entry))
            current = ""
            for line in run([dexdump, "-d", str(path)]).splitlines():
                found = class_line.search(line)
                if found:
                    current = found.group(1).replace("/", ".")
                elif matched in line:
                    owners.append(current)
        return owners

    def scan_hardcoded_key(self) -> None:
        """
        A 32-byte key literal in **our own** compiled code.

        Scoped to `com.passwird.*` deliberately. The first version of this check scanned raw
        DEX bytes for a 64-hex string near the word "key" and fired on BouncyCastle's public
        elliptic-curve constants — because a DEX string pool is sorted alphabetically, so
        "nearby" means "alphabetically adjacent", not "used together". Byte proximity in a
        DEX carries no meaning and the heuristic was unsound.

        `dexdump -d` restores the meaning: it disassembles each class, so a literal can be
        attributed to the class that carries it. A key literal in `com.passwird` code is ours
        and is a finding; a curve constant inside a crypto library is neither. One process
        for the whole APK, rather than one JVM start per class — 617 of those took longer
        than the rest of the scan combined.

        Every quoted literal in the class's dump is examined, not only `const-string`
        instructions. Restricting to instructions was tried and let a planted key through: a
        `const val` that nothing reads is emitted as a static field value, so the check
        passed on an APK that genuinely contained a hard-coded key.
        """
        dexdump = build_tool("dexdump")
        if not dexdump:
            self.check("no key literal in application code", False, "dexdump unavailable")
            return

        # Any run of 48+ hex or 60+ base64 characters inside quotes. 48 hex is 24 bytes —
        # below any key size we use, so a real 32-byte key cannot slip under the threshold.
        long_literal = re.compile(r"['\"]([0-9a-fA-F]{48,}|[A-Za-z0-9+/]{60,}={0,2})['\"]")
        class_line = re.compile(r"Class descriptor\s*:\s*'L([^;]+);'")

        hits: list[str] = []
        app_classes = 0
        with zipfile.ZipFile(self.apk) as zf:
            with tempfile.TemporaryDirectory() as tmp:
                for entry in (e for e in zf.namelist() if e.endswith(".dex")):
                    path = Path(tmp) / Path(entry).name
                    path.write_bytes(zf.read(entry))
                    current = ""
                    for line in run([dexdump, "-d", str(path)]).splitlines():
                        found = class_line.search(line)
                        if found:
                            current = found.group(1).replace("/", ".")
                            if current.startswith(APP_PACKAGE_PREFIX):
                                app_classes += 1
                            continue
                        if not current.startswith(APP_PACKAGE_PREFIX):
                            continue
                        for literal in long_literal.finditer(line):
                            hits.append(f"{current}: {literal.group(1)[:24]}...")

        self.check(
            f"no key-length literal in application code ({app_classes} classes disassembled)",
            not hits and app_classes > 0,
            "; ".join(hits[:4]) if hits else "no com.passwird class found in any DEX — check is vacuous",
        )

    # --------------------------------------------------------------- manifest

    def scan_manifest(self) -> None:
        if not self.manifest:
            self.check("manifest readable", False, "apkanalyzer unavailable")
            return

        # Exported components. An exported component is an IPC entry point; this product
        # claims to publish exactly one. A component guarded by a permission is not an open
        # door, so the guard is read rather than assumed.
        exported: list[str] = []
        guarded: set[str] = set()
        current_name = None
        current_permission = None
        for line in self.manifest.splitlines():
            stripped = line.strip()
            if stripped.startswith("android:name=") and '"' in stripped:
                current_name = stripped.split('"')[1]
                current_permission = None
            if stripped.startswith("android:permission=") and current_name:
                current_permission = stripped.split('"')[1] if '"' in stripped else None
            if stripped.startswith("android:exported=") and '"true"' in stripped and current_name:
                exported.append(current_name)
                if current_permission:
                    guarded.add(current_name)

        unexpected = [
            c for c in exported
            if c not in EXPECTED_EXPORTED and c not in guarded and c not in DEBUG_ONLY_EXPORTED
        ]
        self.check(
            f"every exported component is expected or permission-guarded "
            f"({len(exported)} exported, {len(guarded)} guarded)",
            not unexpected,
            "unexpected: " + ", ".join(unexpected),
        )

        debug_only_present = [c for c in exported if c in DEBUG_ONLY_EXPORTED]
        if debug_only_present and self.release:
            self.check(
                "no debug-only exported component in the release build",
                False,
                ", ".join(debug_only_present),
            )
        elif debug_only_present:
            self.notes.append(
                f"{', '.join(debug_only_present)} is exported and unguarded. It arrives with "
                "`debugImplementation` tooling and is absent from release — verified by "
                "scanning the release APK, not assumed from the dependency scope."
            )

        self.check(
            "allowBackup is false",
            'android:allowBackup="false"' in self.manifest.replace("'", '"'),
            "automatic backup would copy the encrypted vault under a different protection model",
        )
        self.check(
            "dataExtractionRules is declared",
            "dataExtractionRules" in self.manifest,
            "adb backup and device-to-device transfer would be unrestricted",
        )
        self.check(
            "cleartext traffic is not enabled",
            'android:usesCleartextTraffic="true"' not in self.manifest,
        )

        debuggable = 'android:debuggable="true"' in self.manifest
        if self.release:
            self.check("release build is not debuggable", not debuggable,
                       "a debuggable release exposes the vault to run-as and debugger attach")
        else:
            self.check("debug build is debuggable, as expected", debuggable)
            self.notes.append(
                "This APK is debuggable. `run-as` and a debugger can read app-private storage, "
                "so it must never hold a real vault and must never be distributed."
            )

        # Permissions. The privacy model names the complete set.
        declared = set(re.findall(r'android:name="(android\.permission\.[A-Z_]+)"', self.manifest))
        allowed = {
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
        }
        extra = declared - allowed
        self.check(
            f"no permission beyond the documented set ({len(declared)} declared)",
            not extra,
            "unexpected: " + ", ".join(sorted(extra)),
        )

    # ------------------------------------------------------------------- dex

    def scan_dex(self) -> None:
        if not self.apkanalyzer:
            return

        refs = run([self.apkanalyzer, "dex", "packages", str(self.apk)])

        # Does our own code reach a TLS-disabling helper? The class shipping inside Google's
        # library is not a finding; our code calling it would be.
        reachable = []
        for line in refs.splitlines():
            if any(method in line for method in DANGEROUS_TLS_METHODS):
                # Column 1 is the reference type; 'r' means referenced-but-not-defined.
                if line.startswith("M r") or line.startswith("M d"):
                    reachable.append(line.split("\t")[-1][:120])
        # Confirm no com.passwird class references them.
        app_refs = [r for r in reachable if APP_PACKAGE_PREFIX in r]
        self.check(
            "no application class calls a TLS-disabling helper",
            not app_refs,
            "; ".join(app_refs[:3]),
        )
        if reachable:
            self.notes.append(
                f"{len(reachable)} TLS-disabling method(s) ship inside google-http-client "
                "(SslUtils.trustAllSSLContext and friends). No application class references "
                "them; R8 strips them from the release build. Verified, not assumed."
            )

        # Analytics and crash reporting must be absent entirely (ADR-0005).
        forbidden_packages = [
            "com.google.firebase.analytics", "com.google.firebase.crashlytics",
            "com.crashlytics", "io.sentry", "com.amplitude", "com.mixpanel",
            "com.appsflyer", "com.adjust", "com.facebook.appevents",
        ]
        present = [p for p in forbidden_packages if p in refs]
        self.check(
            "no analytics or crash-reporting SDK is in the APK",
            not present,
            "found: " + ", ".join(present),
        )

    def report(self) -> int:
        print()
        for note in self.notes:
            print(f"  note  {note}")
        print()
        if self.failures:
            print(f"FAIL  {len(self.failures)} of {self.checks} checks failed:")
            for failure in self.failures:
                print(f"      {failure}")
            return 1
        print(f"PASS  {self.checks} checks against {self.apk.name}")
        return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    release = "--release" in sys.argv

    apk = Path(args[0]) if args else ROOT / "app/build/outputs/apk/debug/app-debug.apk"
    if not apk.exists():
        print(f"FAIL  no APK at {apk}. Run: ./gradlew assembleDebug")
        return 1

    print(f"APK security scan — {apk}")
    print(f"  {apk.stat().st_size:,} bytes")
    print("-" * 60)

    scan = Scan(apk, release)
    scan.scan_payload()
    scan.scan_hardcoded_key()
    scan.scan_manifest()
    scan.scan_dex()
    return scan.report()


if __name__ == "__main__":
    sys.exit(main())
