#!/bin/bash
# Builds a release into dist/: the server for Linux (deb for Debian 13 and a
# plain program, amd64 and arm64), third-party licenses and, with the release
# key, the signed manifest of dist/release-V (the files that go on GitHub).
#   bash tools/release/build.sh 0.6.0 [release-notes.md]
set -euo pipefail
V=${1:?version}
NOTES=${2:-}
KEY=${EMAILZIT_RELEASE_KEY:-/c/Users/Mili/Ai/release-keys/emailzit-release.key}
cd "$(dirname "$0")/../.."
export GOTMPDIR=$PWD/.gotmp CGO_ENABLED=0
mkdir -p dist
for arch in amd64 arm64; do
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=$V" -o "dist/emailzit-server-$V-linux-$arch" ./cmd/emailzit-server
  GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "dist/emailzit-sendmail-$V-linux-$arch" ./cmd/emailzit-sendmail
done
# Licenses of everything linked into the program (fails on an unknown license).
go run ./tools/licenses -out THIRD_PARTY_LICENSES.md "dist/emailzit-server-$V-linux-amd64"
cp THIRD_PARTY_LICENSES.md "dist/THIRD_PARTY_LICENSES-$V.md"

NFPM="go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.43.0"
export VERSION=$V
for arch in amd64 arm64; do
  rm -rf bin/pkg && mkdir -p bin/pkg
  cp "dist/emailzit-server-$V-linux-$arch" bin/pkg/emailzit-server
  cp "dist/emailzit-sendmail-$V-linux-$arch" bin/pkg/emailzit-sendmail
  rm -f "dist/emailzit-server_${V}_${arch}.deb"
  ARCH=$arch $NFPM package --config packaging/linux/nfpm-server.yaml --packager deb --target dist/ >/dev/null
done

# What goes on GitHub, with the signed manifest.
R="dist/release-$V"
rm -rf "$R" && mkdir -p "$R"
cp "dist/emailzit-server-$V-linux-amd64" "dist/emailzit-server-$V-linux-arm64" \
   "dist/emailzit-server_${V}_amd64.deb" "dist/emailzit-server_${V}_arm64.deb" \
   "dist/THIRD_PARTY_LICENSES-$V.md" packaging/install.sh "$R/"
(cd "$R" && sha256sum $(ls | grep -v '^SHA256SUMS') > SHA256SUMS)
if [ -f "$KEY" ]; then
  go run ./tools/relsign sign -key "$KEY" -version "$V" -dir "$R" ${NOTES:+-notes "$NOTES"}
else
  echo "note: no release key at $KEY; the release is not signed"
fi
echo "built $V"
