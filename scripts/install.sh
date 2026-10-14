#!/bin/sh
set -eu

install_dir="${HOME}/.local/bin"
target="${install_dir}/seamless-input"
profile="${SEAMLESS_INPUT_PROFILE:-${HOME}/.profile}"
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
if [ -z "${checksum}" ] || { [ -z "${asset}" ] && [ -z "${asset_url}" ]; }; then
  printf '%s\n' "Provide a pinned release asset (file or HTTPS URL) and its published SHA-256." >&2
  exit 2
fi

mkdir -p "${install_dir}"
tmp="${target}.new.$$"
backup="${target}.rollback.$$"
trap 'rm -f "${tmp}" "${backup}"' EXIT HUP INT TERM
if [ -n "${asset}" ]; then
  cp "${asset}" "${tmp}"
else
  case "${asset_url}" in
    https://*) curl --fail --location --proto '=https' --tlsv1.2 --output "${tmp}" "${asset_url}" ;;
    *) printf '%s\n' "Remote assets must use HTTPS." >&2; exit 2 ;;
  esac
fi
actual="$(shasum -a 256 "${tmp}" | awk '{print $1}')"
if [ "${actual}" != "${checksum}" ]; then
  printf '%s\n' "Checksum verification failed; existing installation was not changed." >&2
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
