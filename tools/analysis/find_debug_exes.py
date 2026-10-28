#!/usr/bin/env python3
"""Find DOS executables carrying recognizable debug information.

Recognizes Watcom, Microsoft CodeView, Borland Turbo Debugger, COFF symbol
tables used by DJGPP and compatible tools, and LE/LX header debug sections.
These identify debug *formats*, which may be emitted by more than one compiler.

    python3 tools/analysis/find_debug_exes.py /path/to/games
    python3 tools/analysis/find_debug_exes.py /path/to/games --csv debug_exes.csv
"""

import argparse
import csv
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from watcom_debug import DebugInfoError, parse as parse_watcom  # noqa: E402


DEFAULT_ROOT = "."
EXECUTABLE_SUFFIXES = {".exe", ".com", ".dll", ".ovl"}
FIELDS = ("path", "format", "version", "modules", "symbols", "debug_bytes")


def read_at(file, offset, size):
    file.seek(offset)
    return file.read(size)


def mz_image_end(file, file_size):
    """The end of the load image recorded by the DOS MZ header, if valid."""
    header = read_at(file, 0, 6)
    if len(header) != 6 or header[:2] not in (b"MZ", b"ZM"):
        return None
    last_page, pages = struct.unpack_from("<HH", header, 2)
    end = (pages - 1) * 512 + (last_page or 512) if pages else 0
    return end if 28 <= end <= file_size else None


def detect_watcom(file, file_size):
    """Check the Watcom v3 master header, then validate and parse its debug block."""
    if file_size < 32:
        return None
    trailer = read_at(file, file_size - 14, 14)
    if len(trailer) != 14 or trailer[:2] != b"\x86\x83":
        return None
    _, _, _, _, _, lang_size, seg_size, size = struct.unpack("<HBBBBHHI", trailer)
    if (size < 32 or size > file_size or seg_size % 2 or
            lang_size + seg_size + 18 + 14 > size):
        return None
    block = read_at(file, file_size - size, size)
    if len(block) != size:
        return None
    # The existing parser assumes section offsets are in bounds. Check them
    # before calling it, so random files with a matching trailer stay harmless.
    pos = lang_size + seg_size
    end = size - 14
    sections = 0
    while pos + 18 <= end:
        mod, glob, addr, section_size, _ = struct.unpack_from("<IIIIH", block, pos)
        if not (18 <= mod <= glob <= addr <= section_size <= end - pos):
            return None
        pos += section_size
        sections += 1
    if sections == 0 or (pos != end and any(block[pos:end])):
        return None
    try:
        info = parse_watcom(block)
    except (DebugInfoError, ValueError, struct.error, IndexError):
        return None
    if not (info["modules"] or info["globals"] or info["addresses"]):
        return None
    return {"format": "Watcom", "version": info["version"],
            "modules": len(info["modules"]), "symbols": len(info["globals"]),
            "debug_bytes": size}


def detect_codeview(file, file_size):
    """Microsoft Symbol and Type OMF: repeated NBxx signature and EOF back pointer."""
    # TIS Formats Specification, "Symbol and Type Format for Microsoft Executables":
    # https://www.x-ways.net/winhex/kb/ff/PE_EXE.pdf
    if file_size < 32:
        return None
    trailer = read_at(file, file_size - 8, 8)
    signature = trailer[:4]
    if signature not in (b"NB02", b"NB05", b"NB08", b"NB09"):
        return None
    back_offset = struct.unpack_from("<I", trailer, 4)[0]
    base = file_size - back_offset
    if back_offset < 24 or base < 0 or base + 8 >= file_size - 8:
        return None
    leading = read_at(file, base, 8)
    if leading[:4] != signature:
        return None
    directory_offset = struct.unpack_from("<I", leading, 4)[0]
    directory = base + directory_offset
    if directory_offset < 8 or directory + 16 > file_size - 8:
        return None
    header = read_at(file, directory, 16)
    header_size, entry_size, entries = struct.unpack_from("<HHI", header)
    if not (16 <= header_size <= 256 and 12 <= entry_size <= 256 and
            0 < entries <= 1_000_000 and
            directory + header_size + entries * entry_size <= file_size - 8):
        return None
    return {"format": "CodeView", "version": signature.decode("ascii"),
            "modules": "", "symbols": "", "debug_bytes": back_offset}


def detect_borland(file, file_size):
    """Borland TDINFO starts immediately after the MZ image (possibly padded)."""
    # Ralf Brown's Interrupt List, Borland debugging information header:
    # https://www.delorie.com/djgpp/doc/rbinter/it/24/16.html
    image_end = mz_image_end(file, file_size)
    if image_end is None or file_size - image_end < 48:
        return None
    # TLINK may align the appended block to a paragraph boundary.
    window = read_at(file, image_end, min(64, file_size - image_end))
    for delta in range(min(16, len(window) - 48) + 1):
        start = image_end + delta
        header = window[delta:delta + 48]
        if header[:2] != b"\xfb\x52":
            continue
        version, pool_size = struct.unpack_from("<HI", header, 2)
        counts = struct.unpack_from("<12H", header, 8)
        names, _, _, symbols, globals_, modules = counts[:6]
        extension_size = struct.unpack_from("<H", header, 0x2e)[0]
        if (not 1 <= version <= 0x2000 or not names or not symbols or
                globals_ > symbols or modules > symbols or
                not 0 < pool_size < file_size - start or
                extension_size not in (0, 0x10, 0x20) or
                start + 48 + extension_size + symbols * 9 + modules * 16 + pool_size > file_size):
            continue
        pool = read_at(file, file_size - pool_size, pool_size)
        if pool.count(b"\0") < names:
            continue
        return {"format": "Borland TDINFO", "version": f"{version >> 8}.{version & 255:02d}",
                "modules": modules, "symbols": symbols, "debug_bytes": file_size - start}
    return None


def detect_djgpp_coff(file, file_size):
    """Find a DJGPP-style COFF payload and validate its symbol/string tables."""
    # DJGPP COFF specification: https://delorie.com/djgpp/doc/coff/
    image_end = mz_image_end(file, file_size)
    if image_end is None:
        starts = (0,)
    else:
        window = read_at(file, image_end, min(532, file_size - image_end))
        starts = (image_end + pos for pos in range(min(513, len(window) - 19))
                  if window[pos:pos + 2] == b"\x4c\x01")
    for start in starts:
        header = read_at(file, start, 20)
        if len(header) != 20:
            continue
        magic, sections, _, symptr, symbols, optional_size, flags = struct.unpack("<HHIIIHH", header)
        symbol_end = start + symptr + symbols * 18
        if (magic != 0x14c or not 1 <= sections <= 256 or not flags & 2 or
                not 1 <= symbols <= 10_000_000 or not symptr or
                start + 20 + optional_size + sections * 40 > file_size or
                symbol_end + 4 > file_size):
            continue
        string_size = struct.unpack("<I", read_at(file, symbol_end, 4))[0]
        if string_size < 4 or symbol_end + string_size > file_size:
            continue
        # Reject tables containing only anonymous section/linker records.
        table = read_at(file, start + symptr, min(symbols, 10_000) * 18)
        useful = False
        index = 0
        while index * 18 + 18 <= len(table):
            record = table[index * 18:(index + 1) * 18]
            section = struct.unpack_from("<h", record, 12)[0]
            storage, aux = record[16], record[17]
            name = record[:8].split(b"\0", 1)[0]
            if not name and record[:4] == b"\0" * 4:
                name_offset = struct.unpack_from("<I", record, 4)[0]
                if 4 <= name_offset < string_size:
                    name = read_at(file, symbol_end + name_offset,
                                   min(32, string_size - name_offset)).split(b"\0", 1)[0]
            if ((storage in (2, 3) and section > 0 and name and not name.startswith(b".")) or
                    storage == 103):
                useful = True
                break
            index += aux + 1
        if not useful:
            continue
        # This count describes COFF records, including linker and section
        # records, rather than named functions alone.
        return {"format": "COFF symbols", "version": "", "modules": "",
                "symbols": symbols, "debug_bytes": symbols * 18 + string_size}
    return None


def detect_le_lx_debug(file, file_size):
    """Catch debug sections recorded in LE/LX headers, including other formats."""
    # Open Watcom's LE/LX header definition has debug_off/debug_len at 0x98/0x9c:
    # https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h
    if file_size < 0x100 or read_at(file, 0, 2) not in (b"MZ", b"ZM"):
        return None
    le_offset = struct.unpack("<I", read_at(file, 0x3c, 4))[0]
    if le_offset < 0x40 or le_offset + 0xa0 > file_size:
        return None
    header = read_at(file, le_offset, 0xa0)
    if header[:2] not in (b"LE", b"LX") or header[2:8] != bytes(6):
        return None
    objects = struct.unpack_from("<I", header, 0x44)[0]
    page_size = struct.unpack_from("<I", header, 0x28)[0]
    if not 1 <= objects <= 65535 or not 512 <= page_size <= 65536:
        return None
    debug_offset, debug_length = struct.unpack_from("<II", header, 0x98)
    if debug_offset < le_offset + 0xa0 or debug_length < 16 or debug_offset + debug_length > file_size:
        return None
    prefix = read_at(file, debug_offset, 4)
    if prefix == b"\0" * 4:
        return None
    if prefix[:2] == b"NB" and prefix[2:4].isdigit():
        name, version = "CodeView", prefix.decode("ascii")
    else:
        name, version = "LE/LX debug section", ""
    return {"format": name, "version": version, "modules": "",
            "symbols": "", "debug_bytes": debug_length}


DETECTORS = (detect_watcom, detect_codeview, detect_borland,
             detect_djgpp_coff, detect_le_lx_debug)


def paths(root, all_files, errors):
    if os.path.isfile(root):
        yield root
        return
    for directory, subdirs, filenames in os.walk(root, onerror=errors.append):
        subdirs.sort()
        for name in sorted(filenames):
            if all_files or os.path.splitext(name)[1].lower() in EXECUTABLE_SUFFIXES:
                yield os.path.join(directory, name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root", nargs="?", default=DEFAULT_ROOT, help="file or directory to scan (default: current directory)")
    parser.add_argument("--all-files", action="store_true", help="inspect every file, regardless of extension")
    parser.add_argument("--max-files", type=int, help="stop after inspecting this many candidates")
    parser.add_argument("--csv", metavar="FILE", help="also write matches to a CSV file")
    args = parser.parse_args(argv)
    if not os.path.exists(args.root):
        parser.error("path does not exist: " + args.root)
    if args.max_files is not None and args.max_files < 1:
        parser.error("--max-files must be positive")

    errors = []
    inspected = matches = 0
    output = open(args.csv, "w", newline="", encoding="utf-8") if args.csv else None
    try:
        writer = csv.DictWriter(output, FIELDS) if output else None
        if writer:
            writer.writeheader()
        for path in paths(args.root, args.all_files, errors):
            if args.max_files is not None and inspected >= args.max_files:
                break
            inspected += 1
            try:
                with open(path, "rb") as file:
                    file_size = os.fstat(file.fileno()).st_size
                    for detector in DETECTORS:
                        result = detector(file, file_size)
                        if result:
                            row = {"path": path, **result}
                            details = ", ".join(f"{key}={result[key]}" for key in ("modules", "symbols")
                                                if result[key] != "")
                            label = " ".join(part for part in (result["format"], result["version"]) if part)
                            print(f"{path}\t{label}" + (f"\t{details}" if details else ""))
                            if writer:
                                writer.writerow(row)
                            matches += 1
                            break
            except OSError as exc:
                errors.append(exc)
    finally:
        if output:
            output.close()
    for error in errors:
        print(f"warning: {error}", file=sys.stderr)
    print(f"Inspected {inspected} candidates; found {matches} with recognized debug info"
          f"; {len(errors)} read errors.", file=sys.stderr)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
