#!/bin/sh
# 打一个可直接分发的 release 包：二进制 + README + LICENSE。
# 用法：sh scripts/release.sh
set -e
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
TARGET=$(rustc -vV | sed -n 's/^host: //p')
NAME="wx_db_explorer-$VERSION-$TARGET"
DIST="dist/$NAME"

echo "==> building release ($TARGET)"
cargo build --release

rm -rf "$DIST" "dist/$NAME.tar.gz"
mkdir -p "$DIST"
cp target/release/wx_db_explorer "$DIST/"
cp README.md LICENSE "$DIST/"
strip "$DIST/wx_db_explorer" 2>/dev/null || true

tar -czf "dist/$NAME.tar.gz" -C dist "$NAME"
echo
echo "产物："
ls -lh "dist/$NAME.tar.gz" "$DIST/wx_db_explorer" | awk '{print "  " $5, $9}'
echo "sha256："
sha256sum "dist/$NAME.tar.gz"
