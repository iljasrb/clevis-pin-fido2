# Common setup for bats tests. Puts the stub fido2-* binaries (and this
# repo's own scripts) at the front of PATH, real `jose`/coreutils are used
# as-is. See tests/stubs/*.README notes in each stub for the protocol they
# implement -- they exercise the surrounding plumbing (config parsing, JWE
# construction, error paths) with real jose, NOT real hardware/crypto.

repo_root () {
  cd "${BATS_TEST_DIRNAME}/.." && pwd
}

setup_stubs () {
  export PATH="$(repo_root)/tests/stubs:${PATH}"
  export STUB_LOG="${BATS_TEST_TMPDIR}/stub.log"
  : > "${STUB_LOG}"
  unset STUB_FIDO2_TOKENS STUB_FIDO2_NO_TOKEN STUB_FIDO2_CRED_FAIL STUB_FIDO2_ASSERT_FAIL FIDO2_TOKEN TIMEOUT

  # Invoke via explicit `bash` rather than relying on the scripts' own
  # shebang + PATH lookup: behaviorally identical, but portable to any CI
  # runner regardless of whether /bin/bash happens to exist at that path.
  # CLEVIS_FIDO2_REPO_ROOT must be a genuinely exported var, not `local`:
  # these functions get `export -f`'d and re-invoked in fresh subshells
  # (e.g. by `run bash -c "..."`), where a local variable would no longer
  # be in scope.
  export CLEVIS_FIDO2_REPO_ROOT
  CLEVIS_FIDO2_REPO_ROOT="$(repo_root)"
  clevis-encrypt-fido2 () { bash "${CLEVIS_FIDO2_REPO_ROOT}/clevis-encrypt-fido2" "$@"; }
  clevis-decrypt-fido2 () { bash "${CLEVIS_FIDO2_REPO_ROOT}/clevis-decrypt-fido2" "$@"; }
  clevis-fido2-regen () { bash "${CLEVIS_FIDO2_REPO_ROOT}/clevis-fido2-regen" "$@"; }
  export -f clevis-encrypt-fido2 clevis-decrypt-fido2 clevis-fido2-regen
}

jwe_header () {
  # $1 = path to a JWE file; prints the decoded protected header JSON.
  local hdr64
  hdr64="$(cut -d. -f1 "${1}")"
  jose fmt --quote="${hdr64}" --string --b64load --object --output=-
}

jwe_header_field () {
  # $1 = JWE file, $2 = slash path under .clevis.fido2 (e.g. "rp_id")
  local hdr
  hdr="$(jwe_header "${1}")"
  jose fmt --json="${hdr}" --get clevis --get fido2 --get "${2}" --unquote=-
}
