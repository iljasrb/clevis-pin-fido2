# clevis-pin-fido2

⚠️ **Use at own risk and consider this plugin to be experimental right now.** ⚠️

## Requirements

- [libfido2](https://developers.yubico.com/libfido2/)
- [clevis](https://github.com/latchset/clevis)
- A compatible fido2 token (e.g. Yubikey, Nitrokey) that supports the **hmac-secret** extension

You can check whether or not your token is suitable by executing `fido2-token -I /dev/hidraw0 | grep hmac-secret` (use `fido2-token -L` to get the correct `/dev/hidrawX` path). For valid authenticators it will match a line like "extension strings: credProtect, hmac-secret".

## Installation

Copy `clevis-encrypt-fido2` and `clevis-decrypt-fido2` to the `$PATH` directory in which clevis is installed (or any local bin path if it should only work for the current user). Optionally, also copy `clevis-fido2-regen` there (see [Rotating a binding](#rotating-a-binding) below) -- it is not needed at boot time, so it does not need to be reachable from the dracut initramfs.

## Configuration options

See [clevis-encrypt-fido2.1.adoc](clevis-encrypt-fido2.1.adoc) for the full list of
`clevis encrypt fido2 CONFIG` options, including `type`, `cred_id`, `rp_id`, `up`,
`uv`, `pin`, `resident` (create a discoverable/resident credential), `device`,
`aaguid` (pick a specific connected token model instead of the first one found) and
`timeout`.

## Rotating a binding

`clevis luks regen` does not work with this pin (it only understands a small set of
built-in pins). Use `clevis-fido2-regen -d DEV` instead to rotate the hmac-salt of an
existing LUKS2 binding while reusing the same enrolled credential -- see
[clevis-fido2-regen.1.adoc](clevis-fido2-regen.1.adoc) for details.

## Dracut

Copy the contents of `dracut/` to one of the dracut configuration directories: `/usr/lib/dracut/` or `/etc/dracut/`. This module depends on the Clevis module. Due to dracut limitations, `clevis-{decrypt,encrypt}-fido2` scripts must reside in directories that dracut scans for executables (ignores `$PATH`): `/bin:/sbin:/usr/bin:/usr/sbin`.