#!/usr/bin/env bash
#
# Static secret and architecture scan.
#
# Two jobs, both of which fail the build:
#
#   1. No key material, credential or token is embedded anywhere in the tree.
#   2. The architectural boundaries that make the security claims true are actually
#      intact - core modules stay free of Android and Google, secrets stay out of
#      SharedPreferences, and no undocumented network destination appears.
#
# The second job matters as much as the first. "Google is not in the key hierarchy" is a
# claim about the module graph, and a claim about the module graph should be checked by
# something other than good intentions.
#
# Usage: scripts/scan-secrets.sh [--quiet]

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

QUIET=0
[[ "${1:-}" == "--quiet" ]] && QUIET=1

FAILURES=0
CHECKS=0

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
dim()   { [[ $QUIET -eq 1 ]] || printf '\033[2m%s\033[0m\n' "$*"; }

# Source files only. Build output, the git database and the bundled wordlist and fonts are
# not ours to police, and the wordlist is 7776 English words that trip every entropy
# heuristic ever written.
sources() {
  find . \
    -path ./.git -prune -o \
    -path '*/build' -prune -o \
    -path ./.gradle -prune -o \
    -name '*.ttf' -prune -o \
    -name 'wordlist-eff-large.txt' -prune -o \
    -type f \( -name '*.kt' -o -name '*.kts' -o -name '*.java' -o -name '*.xml' \
               -o -name '*.json' -o -name '*.properties' -o -name '*.yml' \) -print
}

# Production sources. Test fixtures are excluded from the credential-literal check for a
# reason that is not a loophole: a test proving secrets never leak has to contain a secret
# to look for. The sentinel values in core/*/src/test are deliberate, and a scanner that
# flagged them would train everyone to ignore it.
production_sources() {
  sources | grep -v '/src/test/' | grep -v '/src/androidTest/'
}

check() {
  local name="$1"; shift
  local pattern="$1"; shift
  local explanation="${1:-}"
  local scope="${SCAN_SCOPE:-all}"

  CHECKS=$((CHECKS + 1))
  local hits
  if [[ "$scope" == "production" ]]; then
    hits="$(production_sources | xargs -r grep -nEI "$pattern" 2>/dev/null | grep -v 'scan-secrets' || true)"
  else
    hits="$(sources | xargs -r grep -nEI "$pattern" 2>/dev/null | grep -v 'scan-secrets' || true)"
  fi

  if [[ -n "$hits" ]]; then
    red "FAIL  $name"
    [[ -n "$explanation" ]] && printf '      %s\n' "$explanation"
    printf '%s\n' "$hits" | head -20 | sed 's/^/      /'
    FAILURES=$((FAILURES + 1))
  else
    dim "ok    $name"
  fi
}

echo "Passwird static security scan"
echo "-----------------------------"

# --- 1. Embedded secrets -----------------------------------------------------------

check "no private key blocks" \
  '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
  'A private key is committed in the source tree.'

check "no AWS access key ids" \
  'AKIA[0-9A-Z]{16}' \
  'What looks like an AWS access key id is present.'

check "no Google API keys" \
  'AIza[0-9A-Za-z_-]{35}' \
  'What looks like a Google API key is present.'

check "no Slack or GitHub tokens" \
  '(xox[baprs]-[0-9A-Za-z-]{10,})|(gh[pousr]_[0-9A-Za-z]{36})' \
  'A service token is present.'

SCAN_SCOPE=production check "no assigned password or secret literals" \
  '(password|passphrase|secret|apiKey|api_key|token)[[:space:]]*=[[:space:]]*"[^"$]{8,}"' \
  'A credential appears to be assigned as a string literal.'

# A 32-byte key rendered as hex or base64 is the shape a hard-coded vault key would take.
check "no hard-coded 256-bit key material" \
  '"[0-9a-fA-F]{64}"|"[A-Za-z0-9+/]{43}="' \
  'A 32-byte constant is embedded, which is the shape of a hard-coded key.'

check "no keystore or signing material" \
  '(keyAlias|keyPassword|storePassword)[[:space:]]*=[[:space:]]*"' \
  'Signing configuration must come from the environment, never the repository.'

# --- 2. Architectural boundaries ---------------------------------------------------

boundary_check() {
  local name="$1"; shift
  local dirs="$1"; shift
  local pattern="$1"; shift
  local explanation="$1"

  CHECKS=$((CHECKS + 1))

  # Word-split deliberately: several checks span more than one module directory. Passing
  # "platform data app" as a single quoted path made find error out and the check pass
  # silently, which is exactly the failure mode a security scanner must not have.
  # shellcheck disable=SC2086
  local existing=()
  local candidate
  for candidate in $dirs; do
    [[ -d "$candidate" ]] && existing+=("$candidate")
  done

  if [[ ${#existing[@]} -eq 0 ]]; then
    red "FAIL  $name"
    printf '      None of the directories exist: %s\n' "$dirs"
    FAILURES=$((FAILURES + 1))
    return
  fi

  local hits
  hits="$(find "${existing[@]}" -path '*/build' -prune -o -name '*.kt' -type f -print 2>/dev/null \
          | xargs -r grep -nEI "$pattern" 2>/dev/null \
          | grep -vE ':[0-9]+:[[:space:]]*(//|\*|/\*)' || true)"

  if [[ -n "$hits" ]]; then
    red "FAIL  $name"
    printf '      %s\n' "$explanation"
    printf '%s\n' "$hits" | head -10 | sed 's/^/      /'
    FAILURES=$((FAILURES + 1))
  else
    dim "ok    $name"
  fi
}

# This is the executable form of the product's central architectural claim.
boundary_check "core modules import no Google code" \
  "core" \
  '^import com\.google\.' \
  'core:* must never depend on Google. Authentication and encryption are separate systems, and Drive is reachable only through the VaultTransport interface.'

boundary_check "core modules import no Android code" \
  "core" \
  '^import (android|androidx)\.' \
  'core:* must stay pure JVM so the security-critical code runs its full test suite without an emulator.'

boundary_check "no vault data in SharedPreferences" \
  "platform data app" \
  '(^import android\.content\.SharedPreferences|getSharedPreferences\(|PreferenceManager|:[[:space:]]*SharedPreferences)' \
  'Sync state and key material must live in the encrypted store. Clearing app data must not reset the rollback watermark.'

boundary_check "no analytics or crash-reporting SDKs" \
  "app core platform data design" \
  '^import (com\.google\.firebase|com\.crashlytics|io\.sentry|com\.amplitude|com\.mixpanel|com\.segment)' \
  'This product ships no telemetry of any kind (ADR-0005).'

# grep -E has no negative lookahead, so this is a match-then-filter rather than one
# pattern. Written the obvious way it silently matched nothing and passed forever, which
# is the worst possible behaviour for a security check.
CHECKS=$((CHECKS + 1))
URL_HITS="$(find core platform design -path '*/build' -prune -o -name '*.kt' -type f -print 2>/dev/null \
  | grep -v '/src/test/' \
  | xargs -r grep -nE '"https?://' 2>/dev/null \
  | grep -vE 'schemas\.android\.com|www\.w3\.org' || true)"

if [[ -n "$URL_HITS" ]]; then
  red "FAIL  no undeclared network destinations"
  printf '      Every outbound destination must be listed in docs/11-privacy-model.md section 2.\n'
  printf '      Only data:drive may reach the network.\n'
  printf '%s\n' "$URL_HITS" | head -10 | sed 's/^/      /'
  FAILURES=$((FAILURES + 1))
else
  dim "ok    no undeclared network destinations"
fi

# --- 3. Logging hygiene ------------------------------------------------------------

CHECKS=$((CHECKS + 1))
LOG_HITS="$(find core platform data app design -path '*/build' -prune -o -name '*.kt' -type f -print 2>/dev/null \
  | xargs -r grep -nEI '(Log\.[dviwe]|println|System\.out)' 2>/dev/null \
  | grep -v '/test/' | grep -v '/androidTest/' || true)"

if [[ -n "$LOG_HITS" ]]; then
  red "FAIL  no logging in production code"
  printf '      A vault must not log. Even a benign-looking statement can interpolate a Secret.\n'
  printf '%s\n' "$LOG_HITS" | head -10 | sed 's/^/      /'
  FAILURES=$((FAILURES + 1))
else
  dim "ok    no logging in production code"
fi

# --- 4. Source hygiene -------------------------------------------------------------

# A raw control byte inside a char or string literal is invisible in review and changes
# behaviour silently. This caught a real defect during development: SecretBytes wiped the
# caller's passphrase array with NUL where a space was intended, which happened to be the
# safer value but was entirely accidental.
CHECKS=$((CHECKS + 1))
CONTROL_HITS="$(python3 - <<'PYEOF' 2>/dev/null || true
import pathlib
bad = []
for path in sorted(pathlib.Path('.').rglob('*.kt')):
    if 'build' in path.parts or '.git' in path.parts:
        continue
    raw = path.read_bytes()
    for index, byte in enumerate(raw):
        if byte < 0x09 or (0x0b <= byte <= 0x1f and byte != 0x0d) or byte == 0x7f:
            bad.append(f"{path}:{raw.count(chr(10).encode(), 0, index) + 1}: control byte 0x{byte:02x}")
            break
print(chr(10).join(bad))
PYEOF
)"

if [[ -n "$CONTROL_HITS" ]]; then
  red "FAIL  no raw control bytes in Kotlin sources"
  printf '      Use an explicit escape. A literal control character is invisible in review.\n'
  printf '%s\n' "$CONTROL_HITS" | head -10 | sed 's/^/      /'
  FAILURES=$((FAILURES + 1))
else
  dim "ok    no raw control bytes in Kotlin sources"
fi

# --- 5. Backup and extraction ------------------------------------------------------

CHECKS=$((CHECKS + 1))
MANIFEST="app/src/main/AndroidManifest.xml"
if [[ -f "$MANIFEST" ]]; then
  if grep -q 'android:allowBackup="false"' "$MANIFEST" \
     && grep -q 'android:dataExtractionRules' "$MANIFEST"; then
    dim "ok    backup and extraction are disabled"
  else
    red "FAIL  backup and extraction are disabled"
    printf '      allowBackup must be false and dataExtractionRules must be set, or Android\n'
    printf '      will copy the vault off-device under a different protection model.\n'
    FAILURES=$((FAILURES + 1))
  fi
else
  dim "skip  manifest not present"
fi

echo
if [[ $FAILURES -eq 0 ]]; then
  green "PASS  $CHECKS checks, 0 failures"
  exit 0
else
  red "FAIL  $CHECKS checks, $FAILURES failure(s)"
  exit 1
fi
