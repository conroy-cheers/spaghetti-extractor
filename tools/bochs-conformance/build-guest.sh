#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
out=${1:-"$root/build/guest"}
mkdir -p "$out"

as --32 "$root/guest/boot.S" -o "$out/boot.o"
ld -m elf_i386 -T "$root/guest/boot.ld" "$out/boot.o" -o "$out/boot.bin"

boot_size=$(stat -c %s "$out/boot.bin")
if (( boot_size != 512 )); then
  echo "boot.bin is $boot_size bytes; expected exactly 512" >&2
  exit 1
fi
boot_signature=$(od -An -tx1 -j510 -N2 "$out/boot.bin" | tr -d '[:space:]')
if [[ "$boot_signature" != 55aa ]]; then
  echo "boot.bin has signature $boot_signature; expected 55aa" >&2
  exit 1
fi

cc -m32 -E -x assembler-with-cpp \
  -I"$root" "$root/guest/guest.S" -o "$out/guest.i"
as --32 "$out/guest.i" -o "$out/guest.o"
ld -m elf_i386 -T "$root/guest/guest.ld" "$out/guest.o" -o "$out/guest.bin"

guest_size=$(stat -c %s "$out/guest.bin")
if (( guest_size > 8192 )); then
  echo "guest.bin is $guest_size bytes; the boot loader supports at most 8192" >&2
  exit 1
fi

dd if=/dev/zero of="$out/guest.img" bs=1024 count=1440 status=none
dd if="$out/boot.bin" of="$out/guest.img" conv=notrunc status=none
dd if="$out/guest.bin" of="$out/guest.img" bs=512 seek=1 conv=notrunc status=none

printf '%s\n' "$out/guest.img"
