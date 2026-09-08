#!/usr/bin/env bash
#
# Scans a connected device's logcat for values that must never be logged.
#
# Step 9 of the device verification pass. `NoSecretsInLogsTest` already asserts this for the
# JVM core, but that test captures stdout/stderr inside a JVM — it cannot see Logcat, cannot
# see what a third-party library logs, and cannot see what the Android framework echoes back.
# Only a real device can.
#
# Usage:
#   scripts/device-log-scan.sh                 # scan the buffer now
#   scripts/device-log-scan.sh --follow        # stream and flag as you use the app
#   scripts/device-log-scan.sh --clear         # clear the buffer, then exit
#
# The values it looks for are the ones docs/16-device-verification.md tells you to type. Use
# those exact strings during the pass, or this scan proves nothing.

set -uo pipefail

PACKAGE="com.passwird.debug"

# The test data from the verification document. Deliberately distinctive so a hit is
# unambiguous rather than a coincidence.
SENTINELS=(
  "Pw-Device-Test-9f3a2c7e"          # the credential's password
  "device-test@example.invalid"      # the credential's username
  "Correct-Horse-Device-Test-2026"   # the master passphrase
  "Device Test Account"              # the credential's title
  "https://device-test.example.invalid"
)

# Shapes that must never appear regardless of the values used above.
PATTERNS=(
  "BEGIN [A-Z ]*PRIVATE KEY"
  "ya29\\."                          # Google OAuth access token prefix
  "1//[0-9A-Za-z_-]{20,}"            # Google refresh token shape
  "[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"  # a recovery key
)

adb_bin() {
  if command -v adb >/dev/null 2>&1; then echo adb
  elif [[ -x /opt/android-sdk/platform-tools/adb ]]; then echo /opt/android-sdk/platform-tools/adb
  elif [[ -x "${ANDROID_HOME:-}/platform-tools/adb" ]]; then echo "${ANDROID_HOME}/platform-tools/adb"
  else return 1
  fi
}

ADB="$(adb_bin)" || { echo "FAIL  adb not found. Install platform-tools or set ANDROID_HOME."; exit 1; }

if ! "$ADB" get-state >/dev/null 2>&1; then
  echo "FAIL  no device. Connect one, enable USB debugging, and check '$ADB devices'."
  exit 1
fi

if [[ "${1:-}" == "--clear" ]]; then
  "$ADB" logcat -c && echo "ok    logcat buffer cleared. Run the flow, then scan again."
  exit 0
fi

build_filter() {
  local first=1
  for value in "${SENTINELS[@]}"; do
    [[ $first -eq 1 ]] && first=0 || printf '|'
    printf '%s' "$(printf '%s' "$value" | sed 's/[.[\*^$()+?{|]/\\&/g')"
  done
  for pattern in "${PATTERNS[@]}"; do
    printf '|%s' "$pattern"
  done
}

FILTER="$(build_filter)"

scan() {
  # -v time keeps timestamps so a hit can be traced back to a step in the checklist.
  if [[ "${1:-}" == "--follow" ]]; then
    "$ADB" logcat -v time | grep --line-buffered -nEi "$FILTER"
  else
    "$ADB" logcat -d -v time | grep -nEi "$FILTER"
  fi
}

echo "Scanning logcat for values that must never appear"
echo "  device:  $("$ADB" shell getprop ro.product.model 2>/dev/null | tr -d '\r') / Android $("$ADB" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
echo "  package: $PACKAGE"
echo "-------------------------------------------------------------"

if [[ "${1:-}" == "--follow" ]]; then
  echo "Streaming. Any line printed below is a FAILURE. Ctrl-C to stop."
  scan --follow
  exit 0
fi

HITS="$(scan || true)"

if [[ -n "$HITS" ]]; then
  echo "FAIL  sensitive values found in logcat:"
  echo "$HITS"
  echo
  echo "      Treat every line above as a security defect. Record it in"
  echo "      docs/16-device-verification.md against test 9.x and stop the pass."
  exit 1
fi

LINES="$("$ADB" logcat -d 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$LINES" -lt 50 ]]; then
  echo "WARN  only $LINES lines in the buffer. Did you run the flow after --clear?"
  echo "      A clean scan of an empty buffer proves nothing."
  exit 2
fi

echo "PASS  no sentinel value or credential-shaped pattern in $LINES lines of logcat"
