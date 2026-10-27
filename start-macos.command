#!/bin/sh
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Python 3.10+ was not found. Use the macOS app release or install Python.'
    read -r _answer
    exit 1
fi
exec python3 -m envscope.desktop
