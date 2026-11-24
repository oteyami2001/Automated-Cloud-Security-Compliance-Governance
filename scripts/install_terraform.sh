#!/usr/bin/env bash
# Install the pinned Terraform version into ~/bin after verifying HashiCorp's published SHA-256.
# Intended for AWS CloudShell (the home directory persists between sessions).
#
#   bash scripts/install_terraform.sh            # installs 1.17.2 (the version CI uses)
set -euo pipefail

VERSION=${TERRAFORM_VERSION:-1.17.2}
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac
ZIP="terraform_${VERSION}_linux_${ARCH}.zip"
BASE="https://releases.hashicorp.com/terraform/${VERSION}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

curl -sSfL -o "$WORK/$ZIP" "$BASE/$ZIP"
curl -sSfL -o "$WORK/SHA256SUMS" "$BASE/terraform_${VERSION}_SHA256SUMS"
(cd "$WORK" && grep " ${ZIP}\$" SHA256SUMS | sha256sum -c -)

mkdir -p "$HOME/bin"
unzip -o -q "$WORK/$ZIP" terraform -d "$HOME/bin"
chmod +x "$HOME/bin/terraform"
case ":$PATH:" in
  *":$HOME/bin:"*) ;;
  *) echo "Add ~/bin to PATH: export PATH=\$HOME/bin:\$PATH" ;;
esac
"$HOME/bin/terraform" version | head -1
