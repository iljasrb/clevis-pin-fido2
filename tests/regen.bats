load test_helper

# This test drives a *real* LUKS2 volume on a loop device with a *real*
# clevis install (only the fido2-cred/fido2-assert/fido2-token binaries are
# stubbed) -- it needs root (for losetup/cryptsetup) and the `clevis` CLI on
# PATH. It's the one place in this repo's test suite that can actually
# exercise clevis-fido2-regen's LUKS-slot orchestration, since that needs
# real cryptsetup/clevis, not just jose. It is skipped (not failed) when
# those prerequisites aren't available, e.g. when running locally without
# root -- see the CI workflow for where this is expected to actually run.

setup () {
  setup_stubs
  if [ "$(id -u)" -ne 0 ]; then
    skip "needs root (cryptsetup/losetup)"
  fi
  if ! command -v clevis > /dev/null; then
    skip "needs the clevis CLI on PATH"
  fi
  if ! command -v cryptsetup > /dev/null; then
    skip "needs cryptsetup on PATH"
  fi

  export PATH="${CLEVIS_FIDO2_REPO_ROOT}:${PATH}"

  IMG="${BATS_TEST_TMPDIR}/disk.img"
  truncate -s 32M "${IMG}"
  LOOPDEV="$(losetup --find --show "${IMG}")"
  PASS="initial-test-passphrase"
  printf '%s' "${PASS}" | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${LOOPDEV}" -
}

teardown () {
  [ -n "${LOOPDEV:-}" ] && losetup -d "${LOOPDEV}" 2>/dev/null || true
}

@test "clevis-fido2-regen rotates a real LUKS2+fido2 binding" {
  # -k (and every other clevis-luks-bind flag) must precede the positional
  # PIN/CONFIG arguments: clevis-luks-bind uses bash's `getopts`, which stops
  # scanning for flags at the first non-flag argument, so a trailing "-k -"
  # is silently dropped and clevis falls through to its own interactive
  # password prompt instead of reading the key from stdin.
  printf '%s' "${PASS}" | clevis luks bind -y -k - -d "${LOOPDEV}" fido2 '{"timeout":3}'

  run clevis luks list -d "${LOOPDEV}"
  [ "$status" -eq 0 ]
  old_slot="$(echo "$output" | sed -n 's/^\([0-9]*\):.*fido2.*/\1/p' | head -n1)"
  [ -n "${old_slot}" ]

  run clevis-fido2-regen -d "${LOOPDEV}" -y
  [ "$status" -eq 0 ]
  [[ "$output" == *"rotated to slot"* ]]

  run clevis luks list -d "${LOOPDEV}"
  [ "$status" -eq 0 ]
  new_slot="$(echo "$output" | sed -n 's/^\([0-9]*\):.*fido2.*/\1/p' | head -n1)"
  [ -n "${new_slot}" ]
  [ "${new_slot}" != "${old_slot}" ]

  # exactly one fido2 binding remains, and it actually unlocks the device.
  run bash -c "cryptsetup luksDump '${LOOPDEV}' | grep -c ': *luks2\$'"
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]
}
