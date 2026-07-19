load test_helper

setup () {
  setup_stubs
}

@test "clevis-encrypt-fido2 --summary" {
  run clevis-encrypt-fido2 --summary
  [ "$status" -eq 0 ]
  [[ "$output" == *"hmac-secret"* ]]
}

@test "clevis-decrypt-fido2 --summary exits 2 (no summary text, matches clevis convention)" {
  run clevis-decrypt-fido2 --summary
  [ "$status" -eq 2 ]
}

@test "clevis-fido2-regen --summary" {
  run clevis-fido2-regen --summary
  [ "$status" -eq 0 ]
  [[ "$output" == *"Rotates the hmac-salt"* ]]
}

@test "round trip: default config" {
  printf 'hello world' | clevis-encrypt-fido2 '{"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  run bash -c "clevis-decrypt-fido2 < '${BATS_TEST_TMPDIR}/j.jwe'"
  [ "$status" -eq 0 ]
  [ "$output" == "hello world" ]
}

@test "round trip: custom rp_id/type/resident preserved in JWE header" {
  printf 'secret' | clevis-encrypt-fido2 '{"rp_id":"my.rp","type":"eddsa","resident":true,"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  [ "$(jwe_header_field "${BATS_TEST_TMPDIR}/j.jwe" rp_id)" == "my.rp" ]
  [ "$(jwe_header_field "${BATS_TEST_TMPDIR}/j.jwe" type)" == "eddsa" ]
  [ "$(jwe_header_field "${BATS_TEST_TMPDIR}/j.jwe" resident)" == "true" ]
  run bash -c "clevis-decrypt-fido2 < '${BATS_TEST_TMPDIR}/j.jwe'"
  [ "$status" -eq 0 ]
  [ "$output" == "secret" ]
}

@test "aaguid selection picks the matching connected token" {
  export STUB_FIDO2_TOKENS="/dev/null aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
/dev/zero bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  printf 'x' | clevis-encrypt-fido2 '{"aaguid":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","timeout":3}' > "${BATS_TEST_TMPDIR}/j.jwe"
  grep -q '^fido2-assert .*/dev/zero' "${STUB_LOG}"
}

@test "aaguid with no matching token times out with a distinct message" {
  export STUB_FIDO2_TOKENS="/dev/null aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  run bash -c "printf x | clevis-encrypt-fido2 '{\"aaguid\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\",\"timeout\":1}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"No connected token matches the configured aaguid"* ]]
}

@test "no token connected: fails within the configured timeout, not the default" {
  export STUB_FIDO2_NO_TOKEN=1
  run bash -c "printf x | clevis-encrypt-fido2 '{\"timeout\":1}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"No FIDO2 token found within 1 seconds"* ]]
}

@test "fido2-cred failure surfaces captured stderr" {
  export STUB_FIDO2_CRED_FAIL="stub: simulated PIN error"
  run bash -c "printf x | clevis-encrypt-fido2 '{\"timeout\":2}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"could not create FIDO2 credential"* ]]
  [[ "$output" == *"stub: simulated PIN error"* ]]
}

@test "fido2-assert failure surfaces captured stderr on encrypt" {
  export STUB_FIDO2_ASSERT_FAIL="stub: simulated assert error"
  run bash -c "printf x | clevis-encrypt-fido2 '{\"timeout\":2}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"could not generate key"* ]]
  [[ "$output" == *"stub: simulated assert error"* ]]
}

@test "fido2-assert failure surfaces captured stderr on decrypt" {
  printf 'x' | clevis-encrypt-fido2 '{"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  export STUB_FIDO2_ASSERT_FAIL="stub: simulated assert error"
  run bash -c "clevis-decrypt-fido2 < '${BATS_TEST_TMPDIR}/j.jwe'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"could not generate key"* ]]
  [[ "$output" == *"stub: simulated assert error"* ]]
}

@test "malformed JSON config is rejected" {
  run bash -c "printf x | clevis-encrypt-fido2 'not-json'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"Configuration is malformed"* ]]
}

@test "invalid type is rejected" {
  run bash -c "printf x | clevis-encrypt-fido2 '{\"type\":\"bogus\"}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"'type' must be one of"* ]]
}

@test "invalid up (non-boolean JSON value) is rejected, not silently defaulted" {
  run bash -c "printf x | clevis-encrypt-fido2 '{\"up\":\"false\"}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"'up' must be a boolean"* ]]
}

@test "invalid timeout is rejected" {
  run bash -c "printf x | clevis-encrypt-fido2 '{\"timeout\":\"abc\"}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"'timeout' must be a non-negative integer"* ]]
}

@test "invalid aaguid length is rejected" {
  run bash -c "printf x | clevis-encrypt-fido2 '{\"aaguid\":\"deadbeef\"}'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"'aaguid' must be a 32-character hex string"* ]]
}

@test "decrypt rejects a JWE with a corrupt timeout header instead of crashing" {
  printf 'x' | clevis-encrypt-fido2 '{"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  hdr64="$(cut -d. -f1 "${BATS_TEST_TMPDIR}/j.jwe")"
  hdr="$(jose fmt --quote="${hdr64}" --string --b64load --object --output=-)"
  hdr="$(jose fmt -j "${hdr}" -g clevis -g fido2 -q notanumber -s timeout -UUUo-)"
  newhdr64="$(jose fmt -j "${hdr}" -o- | jose b64 enc -I- -o-)"
  full="$(cat "${BATS_TEST_TMPDIR}/j.jwe")"
  rest="${full#*.}"
  printf '%s.%s' "${newhdr64}" "${rest}" > "${BATS_TEST_TMPDIR}/corrupt.jwe"
  run bash -c "clevis-decrypt-fido2 < '${BATS_TEST_TMPDIR}/corrupt.jwe'"
  [ "$status" -eq 1 ]
  [[ "$output" == *"'timeout' header parameter is corrupt"* ]]
}
