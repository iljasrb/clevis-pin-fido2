load test_helper

# Exercises clevis-fido2-regen's header-reading and CONFIG-reconstruction
# logic (decode_header/get_field, and the field-extraction + new_cfg
# construction block) against a *real* JWE produced by the real
# clevis-encrypt-fido2 (stubbed hardware only) -- no LUKS/cryptsetup/root
# needed. This is the part of clevis-fido2-regen that reads an existing
# binding's metadata and rebuilds a CONFIG to re-encrypt with; a bug here
# breaks the tool before it even gets to the LUKS slot orchestration that
# tests/regen.bats (root-gated) exercises.

setup () {
  setup_stubs
  # Pull decode_header/get_field verbatim from the real script rather than
  # re-implementing them, so this test tracks the actual code.
  eval "$(sed -n '/^decode_header ()/,/^find_fido2_slots ()/p' "${CLEVIS_FIDO2_REPO_ROOT}/clevis-fido2-regen" | sed '$d')"
}

reconstruct_cfg () {
  # $1 = decoded header JSON; echoes the CONFIG object clevis-fido2-regen
  # would rebuild from it (same logic as the real script).
  local hdr="${1}" type rp_id cred_id uv up pin resident device timeout aaguid new_cfg
  type="$(get_field "${hdr}" clevis/fido2/type 1)"
  rp_id="$(get_field "${hdr}" clevis/fido2/rp_id 1)"
  cred_id="$(get_field "${hdr}" clevis/fido2/cred_id 1)"
  uv="$(get_field "${hdr}" clevis/fido2/uv 1)"
  up="$(get_field "${hdr}" clevis/fido2/up 1)"
  pin="$(get_field "${hdr}" clevis/fido2/pin 1)"
  resident="$(get_field "${hdr}" clevis/fido2/resident 0)"
  device="$(get_field "${hdr}" clevis/fido2/device 0)"
  timeout="$(get_field "${hdr}" clevis/fido2/timeout 0)"
  aaguid="$(get_field "${hdr}" clevis/fido2/aaguid 0)"

  new_cfg='{}'
  new_cfg="$(jose fmt -j "${new_cfg}" -q "${type}" -s type -Uo-)"
  new_cfg="$(jose fmt -j "${new_cfg}" -q "${rp_id}" -s rp_id -Uo-)"
  new_cfg="$(jose fmt -j "${new_cfg}" -q "${cred_id}" -s cred_id -Uo-)"
  new_cfg="$(jose fmt -j "${new_cfg}" -j "${up}" -s up -Uo-)"
  new_cfg="$(jose fmt -j "${new_cfg}" -j "${uv}" -s uv -Uo-)"
  new_cfg="$(jose fmt -j "${new_cfg}" -j "${pin}" -s pin -Uo-)"
  [ -n "${resident}" ] && new_cfg="$(jose fmt -j "${new_cfg}" -j "${resident}" -s resident -Uo-)"
  [ -n "${device}" ] && new_cfg="$(jose fmt -j "${new_cfg}" -q "${device}" -s device -Uo-)"
  [ -n "${timeout}" ] && new_cfg="$(jose fmt -j "${new_cfg}" -q "${timeout}" -s timeout -Uo-)"
  [ -n "${aaguid}" ] && new_cfg="$(jose fmt -j "${new_cfg}" -q "${aaguid}" -s aaguid -Uo-)"
  echo "${new_cfg}"
}

@test "get_field extracts mandatory and optional fields from a real JWE header" {
  printf 'x' | clevis-encrypt-fido2 '{"rp_id":"my.rp","timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  jwe="$(cat "${BATS_TEST_TMPDIR}/j.jwe")"
  hdr="$(decode_header "${jwe}")"

  [ "$(get_field "${hdr}" clevis/pin 1)" == "fido2" ]
  [ "$(get_field "${hdr}" clevis/fido2/rp_id 1)" == "my.rp" ]
  [ "$(get_field "${hdr}" clevis/fido2/type 1)" == "es256" ]
  # optional, absent-from-config field: must not error, must be empty.
  [ -z "$(get_field "${hdr}" clevis/fido2/aaguid 0)" ]
}

@test "reconstructed CONFIG round-trips through clevis-encrypt-fido2 (default config)" {
  printf 'x' | clevis-encrypt-fido2 '{"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  jwe="$(cat "${BATS_TEST_TMPDIR}/j.jwe")"
  hdr="$(decode_header "${jwe}")"
  new_cfg="$(reconstruct_cfg "${hdr}")"

  run bash -c "printf y | clevis-encrypt-fido2 '${new_cfg}'"
  [ "$status" -eq 0 ]
}

@test "reconstructed CONFIG round-trips with every optional field set (resident/device/aaguid/timeout)" {
  printf 'x' | clevis-encrypt-fido2 '{"rp_id":"my.rp","type":"eddsa","resident":true,"device":"/dev/null","timeout":5,"aaguid":"2fc0579f811347eab116bb5a8db9202a"}' > "${BATS_TEST_TMPDIR}/j.jwe"
  jwe="$(cat "${BATS_TEST_TMPDIR}/j.jwe")"
  hdr="$(decode_header "${jwe}")"
  new_cfg="$(reconstruct_cfg "${hdr}")"

  [[ "${new_cfg}" == *'"resident":true'* ]]
  [[ "${new_cfg}" == *'"device":"/dev/null"'* ]]
  [[ "${new_cfg}" == *'"aaguid":"2fc0579f811347eab116bb5a8db9202a"'* ]]

  run bash -c "printf y | clevis-encrypt-fido2 '${new_cfg}'"
  [ "$status" -eq 0 ]
}

@test "reconstructed CONFIG preserves non-default up/uv/pin booleans" {
  printf 'x' | clevis-encrypt-fido2 '{"up":false,"uv":true,"pin":true,"timeout":2}' > "${BATS_TEST_TMPDIR}/j.jwe"
  jwe="$(cat "${BATS_TEST_TMPDIR}/j.jwe")"
  hdr="$(decode_header "${jwe}")"
  new_cfg="$(reconstruct_cfg "${hdr}")"

  [[ "${new_cfg}" == *'"up":false'* ]]
  [[ "${new_cfg}" == *'"uv":true'* ]]
  [[ "${new_cfg}" == *'"pin":true'* ]]

  run bash -c "printf y | clevis-encrypt-fido2 '${new_cfg}'"
  [ "$status" -eq 0 ]
}
