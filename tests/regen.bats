load test_helper

# This test drives a *real* LUKS2 volume with a *real* clevis + cryptsetup
# install (only the fido2-cred/fido2-assert/fido2-token binaries are
# stubbed, see tests/stubs/). The LUKS2 volume is a plain image file, which
# cryptsetup can format/rekey without root or loop devices, so this runs
# anywhere clevis and cryptsetup are installed. It is skipped (not failed)
# when those prerequisites are missing.

setup () {
  setup_stubs
  command -v clevis > /dev/null || skip "needs the clevis CLI on PATH"
  command -v cryptsetup > /dev/null || skip "needs cryptsetup on PATH"

  # clevis dispatches to clevis-{encrypt,decrypt}-fido2 by PATH lookup and
  # runs them via their own shebang, so the repo scripts must be reachable
  # as executables. Shim them through `env bash` instead of adding the repo
  # root to PATH directly, so the test also works on hosts where /bin/bash
  # (the scripts' shebang) doesn't exist -- e.g. NixOS dev machines.
  mkdir -p "${BATS_TEST_TMPDIR}/shims"
  local f
  for f in clevis-encrypt-fido2 clevis-decrypt-fido2 clevis-fido2-regen; do
    printf '#!/usr/bin/env bash\nexec bash "%s" "$@"\n' "${CLEVIS_FIDO2_REPO_ROOT}/${f}" > "${BATS_TEST_TMPDIR}/shims/${f}"
    chmod +x "${BATS_TEST_TMPDIR}/shims/${f}"
  done
  export PATH="${BATS_TEST_TMPDIR}/shims:${PATH}"

  IMG="${BATS_TEST_TMPDIR}/disk.img"
  truncate -s 32M "${IMG}"
  PASS="initial-test-passphrase"
  printf '%s' "${PASS}" | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "${IMG}" -

  # clevis-fido2-regen writes its LUKS header backup to the current
  # directory; keep that inside the test tmpdir.
  cd "${BATS_TEST_TMPDIR}"
}

@test "clevis-fido2-regen rotates a real LUKS2+fido2 binding" {
  # -k (and every other clevis-luks-bind flag) must precede the positional
  # PIN/CONFIG arguments: clevis-luks-bind uses bash's `getopts`, which stops
  # scanning for flags at the first non-flag argument.
  printf '%s' "${PASS}" | clevis luks bind -y -k - -d "${IMG}" fido2 '{"timeout":3}'

  run clevis luks list -d "${IMG}"
  echo "clevis luks list (before): ${output}"
  [ "$status" -eq 0 ]
  old_slot="$(echo "$output" | sed -n 's/^\([0-9]*\):.*fido2.*/\1/p' | head -n1)"
  [ -n "${old_slot}" ]

  run clevis-fido2-regen -d "${IMG}" -y
  echo "clevis-fido2-regen output: ${output}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"rotated to slot"* ]]

  run clevis luks list -d "${IMG}"
  echo "clevis luks list (after): ${output}"
  [ "$status" -eq 0 ]
  new_slot="$(echo "$output" | sed -n 's/^\([0-9]*\):.*fido2.*/\1/p' | head -n1)"
  [ -n "${new_slot}" ]
  [ "${new_slot}" != "${old_slot}" ]

  # Exactly two keyslots remain -- slot 0 (the original password from
  # luksFormat) and the rotated fido2 slot -- backed by exactly one clevis
  # token. (clevis-fido2-regen itself already verified the new slot unlocks
  # the device before removing the old one.)
  run bash -c "cryptsetup luksDump '${IMG}' | grep -c ': *luks2\$'"
  echo "keyslot count: ${output}"
  [ "$status" -eq 0 ]
  [ "$output" -eq 2 ]
  run bash -c "cryptsetup luksDump '${IMG}' | grep -c ': clevis\$'"
  echo "clevis token count: ${output}"
  [ "$status" -eq 0 ]
  [ "$output" -eq 1 ]

  # The original password still unlocks slot 0.
  printf '%s' "${PASS}" | cryptsetup open --test-passphrase --key-slot 0 "${IMG}"
}
