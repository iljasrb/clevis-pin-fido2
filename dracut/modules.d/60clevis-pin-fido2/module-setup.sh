#!/bin/bash
# Copyright (c) 2024 Benjamino Masyura <benjama@keemail.me>
#
# _arch and the "instmods =module" syntax below are part of dracut's own
# module-setup.sh calling convention: _arch is set by the dracut framework
# before sourcing this file, and "instmods =PATH" is dracut's own DSL, not a
# literal shell assignment. Both are false positives under plain shellcheck.
# shellcheck disable=SC2154,SC2283

check() {
    require_binaries clevis-decrypt-fido2 fido2-token fido2-assert jose head tail cut wc printf base64 dd sleep grep cat mktemp sed tr rm || return 1
    return 0
}

depends() {
    echo clevis udev-rules
    return 0
}

install() {
    inst_multiple clevis-decrypt-fido2 fido2-token fido2-assert jose head tail cut wc printf base64 dd sleep grep cat mktemp sed tr rm
    inst_libdir_file \
        {"tls/$_arch/",tls/,"$_arch/",}"libfido2.so.*" \
        {"tls/$_arch/",tls/,"$_arch/",}"libz.so.*" \
        {"tls/$_arch/",tls/,"$_arch/",}"libcbor.so.*" \
        {"tls/$_arch/",tls/,"$_arch/",}"libhidapi-hidraw.so.*"
}

installkernel() {
    hostonly='' instmods =drivers/hid/usbhid
}


