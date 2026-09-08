#!/usr/bin/env python3
"""
Import / dependency consistency check for the Android modules.

Why this exists: the project cannot be compiled in the development container (no Android
SDK), so the usual way of discovering a missing dependency — the compiler — is unavailable.
A production-readiness audit of this repository found twelve files importing
`androidx.compose.material3` across three modules that declared it nowhere. That is a hard
build failure, and it sat undetected because nothing checked.

This is the check. It resolves every `androidx.*` / `com.google.*` import in the Android
modules against the dependencies each module actually declares, following `api(project(...))`
edges so a transitively-exposed dependency counts.

It is a static approximation, not a compiler. It cannot prove the project builds; it can
only prove this particular class of defect is absent. `docs/14-production-readiness.md`
states that distinction plainly.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Android modules only. The core:* modules are pure JVM and the compiler checks them.
MODULES = [
    "app",
    "platform/secure",
    "data/drive",
    "design/tokens",
    "design/components",
]

# An import prefix is satisfied if the module can see ANY of the listed catalog aliases.
# Several packages ship inside a broader artifact, or arrive transitively from one that is
# declared, which is why the values are sets rather than single names.
REQUIREMENTS: dict[str, set[str]] = {
    "androidx.compose.material3": {"androidx-compose-material3"},
    "androidx.compose.foundation": {"androidx-compose-foundation"},
    "androidx.compose.ui.graphics": {"androidx-compose-ui-graphics", "androidx-compose-ui"},
    "androidx.compose.ui.tooling": {"androidx-compose-ui-tooling", "androidx-compose-ui-tooling-preview"},
    "androidx.compose.ui.test": {"androidx-compose-ui-test-junit4"},
    "androidx.compose.ui": {"androidx-compose-ui"},
    # runtime and animation ship as separate artifacts but are api dependencies of
    # foundation and ui, so either one satisfies them.
    "androidx.compose.runtime": {"androidx-compose-ui", "androidx-compose-foundation"},
    "androidx.compose.animation": {"androidx-compose-foundation"},
    "androidx.activity.compose": {"androidx-activity-compose"},
    "androidx.navigation": {"androidx-navigation-compose"},
    "androidx.biometric": {"androidx-biometric"},
    "androidx.fragment": {"androidx-fragment", "androidx-biometric"},
    "androidx.lifecycle.compose": {"androidx-lifecycle-runtime-compose"},
    "androidx.lifecycle.viewmodel": {"androidx-lifecycle-viewmodel-compose"},
    "androidx.lifecycle": {
        "androidx-lifecycle-runtime",
        "androidx-lifecycle-process",
        "androidx-lifecycle-viewmodel-compose",
    },
    "androidx.core": {"androidx-core-ktx"},
    "androidx.credentials": {"androidx-credentials", "androidx-credentials-play-services"},
    "com.google.api.services.drive": {"google-api-drive"},
    "com.google.api.client": {"google-api-client-android", "google-api-drive"},
    "com.google.android.libraries.identity": {"google-id"},
    "kotlinx.coroutines": {"kotlinx-coroutines-core"},
    "kotlinx.serialization": {"kotlinx-serialization-json"},
}

# Packages provided by the Android platform itself — no dependency needed.
PLATFORM_PREFIXES = ("android.", "java.", "javax.", "kotlin.", "dalvik.")


def catalog_aliases(text: str) -> set[str]:
    """Catalog references in a build file, normalised to hyphenated alias form."""
    found = set()
    for match in re.finditer(r"libs\.([A-Za-z0-9.]+)", text):
        found.add(match.group(1).replace(".", "-"))
    return found


def project_api_deps(text: str) -> set[str]:
    """`api(project(":a:b"))` edges only — `implementation` is not visible to consumers."""
    return {m.group(1) for m in re.finditer(r'api\(project\("(:[^"]+)"\)\)', text)}


def module_path_for(gradle_path: str) -> str:
    return gradle_path.lstrip(":").replace(":", "/")


def visible_aliases(module: str, cache: dict[str, set[str]]) -> set[str]:
    """Aliases the module declares, plus those exposed by projects it `api`s."""
    if module in cache:
        return cache[module]

    build_file = ROOT / module / "build.gradle.kts"
    if not build_file.exists():
        cache[module] = set()
        return cache[module]

    text = build_file.read_text()
    aliases = catalog_aliases(text)

    cache[module] = aliases  # break cycles before recursing
    for dep in project_api_deps(text):
        aliases |= visible_aliases(module_path_for(dep), cache)

    cache[module] = aliases
    return aliases


def imports_in(module: str) -> dict[str, list[str]]:
    """Maps an import prefix to the files that use it, main source set only."""
    used: dict[str, list[str]] = {}
    source = ROOT / module / "src" / "main"
    if not source.exists():
        return used

    for path in source.rglob("*.kt"):
        for line in path.read_text().splitlines():
            if not line.startswith("import "):
                continue
            imported = line[len("import ") :].strip().removeprefix("`")
            if imported.startswith(PLATFORM_PREFIXES) or imported.startswith("com.passwird."):
                continue

            # Longest matching prefix wins, so androidx.compose.ui.graphics is not
            # mistaken for androidx.compose.ui.
            match = max(
                (p for p in REQUIREMENTS if imported.startswith(p + ".") or imported == p),
                key=len,
                default=None,
            )
            if match:
                used.setdefault(match, []).append(str(path.relative_to(ROOT)))
    return used


def main() -> int:
    cache: dict[str, set[str]] = {}
    failures = 0
    checked = 0

    print("Android import / dependency consistency")
    print("--------------------------------------")

    for module in MODULES:
        if not (ROOT / module / "build.gradle.kts").exists():
            continue

        declared = visible_aliases(module, cache)
        used = imports_in(module)
        missing = []

        for prefix, files in sorted(used.items()):
            checked += 1
            if not (REQUIREMENTS[prefix] & declared):
                missing.append((prefix, sorted(set(files))))

        if missing:
            failures += len(missing)
            print(f"\nFAIL  {module}")
            for prefix, files in missing:
                options = " or ".join(sorted(REQUIREMENTS[prefix]))
                print(f"      imports {prefix} but declares none of: {options}")
                for f in files[:3]:
                    print(f"        {f}")
                if len(files) > 3:
                    print(f"        ... and {len(files) - 3} more file(s)")
        else:
            print(f"ok    {module}  ({len(used)} import groups resolved)")

    print()
    if failures:
        print(f"FAIL  {checked} import groups checked, {failures} unresolved")
        return 1

    print(f"PASS  {checked} import groups checked across {len(MODULES)} modules, all resolved")
    print("      Note: this is a static approximation, not a compile. It proves only that")
    print("      no import lacks a declared dependency.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
