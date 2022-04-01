#! /bin/sh
# Get version from git describe, generate C source code declaring
# version[] variable.  If invoked without arguments, outputsi version to
# stdout; otherwise updates the specified file.
SRCDIR="$(dirname "$(readlink -f "$0")")"
REV=$(cd "$SRCDIR" && git describe '--match=v*' --always --dirty 2>/dev/null \
    | sed -e 's/^v//;s/-dirty$/~dirty/')
# Note: s/-dirty/~dirty/ to ensure proper ordering when the output is
# used as Debian package version.
if [ -z "$REV" ]; then REV=na; fi
C="extern const char version[] = \"$REV\";"
if [ -z "$1" ]; then
    echo "$REV"
else
    if [ "$(cat "$1" 2>/dev/null)" != "$C" ]; then echo "$C" > "$1"; fi
fi
