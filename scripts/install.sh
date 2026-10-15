#!/bin/sh
set -eu

install_dir="${HOME}/.local/bin"
target="${install_dir}/seamless-input"
if [ -n "${SEAMLESS_INPUT_PROFILE:-}" ]; then
  profile="${SEAMLESS_INPUT_PROFILE}"
elif [ "${SHELL##*/}" = "zsh" ]; then
  profile="${ZDOTDIR:-${HOME}}/.zprofile"
else
  profile="${HOME}/.profile"
fi
marker="# SeamlessInput user PATH"

if [ "${1:-}" = "--uninstall" ]; then
  rm -f "${target}"
  if [ -f "${profile}" ]; then
    clean_profile="${profile}.seamless-input-clean.$$"
    awk -v marker="${marker}" '
      $0 == marker { skip_next = 1; next }
      skip_next && $0 == "export PATH=\"$HOME/.local/bin:$PATH\"" { skip_next = 0; next }
      { skip_next = 0; print }
    ' "${profile}" > "${clean_profile}"
    mv "${clean_profile}" "${profile}"
  fi
  printf '%s\n' "Removed the SeamlessInput executable. Pairing identities and configuration were preserved."
  exit 0
fi

asset="${SEAMLESS_INPUT_ASSET_FILE:-}"
asset_url="${SEAMLESS_INPUT_ASSET_URL:-}"
checksum="${SEAMLESS_INPUT_SHA256:-}"
attestation="${SEAMLESS_INPUT_ATTESTATION_FILE:-}"
attestation_url="${SEAMLESS_INPUT_ATTESTATION_URL:-}"
expected_tag="${SEAMLESS_INPUT_EXPECTED_TAG:-}"
if [ -z "${checksum}" ] || [ -z "${expected_tag}" ] || { [ -z "${asset}" ] && [ -z "${asset_url}" ]; } || { [ -z "${attestation}" ] && [ -z "${attestation_url}" ]; }; then
  printf '%s\n' "Provide a release asset, its SHA-256, and its GitHub provenance attestation." >&2
  exit 2
fi
if ! printf '%s' "${expected_tag}" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
  printf '%s\n' "Expected tag must be a reviewed semantic release tag." >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  printf '%s\n' "GitHub CLI is required to verify release provenance." >&2
  exit 2
fi

mkdir -p "${install_dir}"
tmp="${target}.new.$$"
backup="${target}.rollback.$$"
attestation_tmp="${target}.attestation.$$"
trap 'rm -f "${tmp}" "${backup}" "${attestation_tmp}"' EXIT HUP INT TERM
if [ -n "${asset}" ]; then
  cp "${asset}" "${tmp}"
else
  case "${asset_url}" in
    https://*) curl --fail --location --proto '=https' --tlsv1.2 --output "${tmp}" "${asset_url}" ;;
    *) printf '%s\n' "Remote assets must use HTTPS." >&2; exit 2 ;;
  esac
fi
if [ -n "${attestation}" ]; then
  cp "${attestation}" "${attestation_tmp}"
else
  case "${attestation_url}" in
    https://*) curl --fail --location --proto '=https' --tlsv1.2 --output "${attestation_tmp}" "${attestation_url}" ;;
    *) printf '%s\n' "Remote attestations must use HTTPS." >&2; exit 2 ;;
  esac
fi
actual="$(shasum -a 256 "${tmp}" | awk '{print $1}')"
if [ "${actual}" != "${checksum}" ]; then
  printf '%s\n' "Checksum verification failed; existing installation was not changed." >&2
  exit 1
fi
if ! gh attestation verify "${tmp}" --repo lanchuske/seamless-input --bundle "${attestation_tmp}" --source-ref "refs/tags/${expected_tag}" >/dev/null; then
  printf '%s\n' "Provenance verification failed; existing installation was not changed." >&2
  exit 1
fi
chmod 755 "${tmp}"
if [ -f "${target}" ]; then cp "${target}" "${backup}"; fi
if ! mv "${tmp}" "${target}"; then
  if [ -f "${backup}" ]; then mv "${backup}" "${target}"; fi
  exit 1
fi
if [ ! -f "${profile}" ] || ! grep -Fq "${marker}" "${profile}"; then
  {
    printf '\n%s\n' "${marker}"
    printf '%s\n' 'export PATH="$HOME/.local/bin:$PATH"'
  } >> "${profile}"
fi
printf '%s\n' "Installed for the current user. Open a new terminal and run: seamless-input doctor"
