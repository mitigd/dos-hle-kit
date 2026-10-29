#!/usr/bin/env python3
"""Extract 16-bit Borland TDINFO symbols into kit CSVs and gen_decomp JSON.

Supports the packed 48-byte FB52 header (TDINFO 1.x through 3.x) appended
at the MZ image end, with up to 16 bytes of padding. TD32 is not supported.
Record layouts cross-checked against:
https://github.com/ramikg/tdinfo-parser/blob/master/tdinfo_structs.py
Types and scoped parameters are recovered as evidence. Complete call signatures
can be supplied with --signatures after checking the ABI against the code. MZ addresses include the kit loader's 100h PSP prefix.
"""
import argparse
import csv
import json
import os
import struct
import sys

from watcom_debug import DebugInfoError


def parse(data):
    """Return a gen_decomp-compatible document; reject truncated/unsupported data."""
    def fail(message):
        raise DebugInfoError(message)

    if len(data) < 28 or data[:2] not in (b'MZ', b'ZM'):
        fail('not an MZ executable')
    last, pages = struct.unpack_from('<HH', data, 2)
    image_end = (pages - 1) * 512 + (last or 512) if pages else 0
    header_size = struct.unpack_from('<H', data, 8)[0] * 16
    if not 28 <= header_size < image_end <= len(data) or last > 511:
        fail('invalid MZ image bounds')
    if len(data) >= 64:
        new_header = struct.unpack_from('<I', data, 0x3c)[0]
        if new_header >= 64 and data[new_header:new_header + 2] in (b'NE', b'LE', b'LX', b'PE'):
            fail('only real-mode MZ TDINFO is supported')
    start = next((p for p in range(image_end, min(image_end + 17, len(data) - 47))
                  if data[p:p + 2] == b'\xfb\x52'), None)
    if start is None:
        fail('no Borland TDINFO header after MZ image')
    minor, major, pool_size = struct.unpack_from('<BBI', data, start + 2)
    if major not in (1, 2, 3):
        fail('unsupported TDINFO version %d.%02d' % (major, minor))
    counts = struct.unpack_from('<12H', data, start + 8)
    names_n, types_n, members_n, symbols_n, globals_n, modules_n, _, scopes_n, lines_n, files_n, segments_n, corr_n = counts
    extension = struct.unpack_from('<H', data, start + 46)[0]
    pool_start = len(data) - pool_size
    if not pool_size or pool_start < start + 48 + extension or globals_n > symbols_n:
        fail('invalid TDINFO header or name pool size')
    pos = start + 48 + extension

    def table(count, size):
        nonlocal pos
        begin = pos
        pos += count * size
        if pos > pool_start:
            fail('TDINFO tables overlap name pool')
        return begin

    symbols_at = table(symbols_n, 9)
    modules_at = table(modules_n, 16)
    table(files_n, 6)
    table(lines_n, 4)
    scopes_at = table(scopes_n, 12)
    segments_at = table(segments_n, 16)
    table(corr_n, 8)
    types_at = table(types_n, 8)
    table(members_n, 5)
    names = ['']
    p = pool_start
    for _ in range(names_n):
        end = data.find(b'\0', p)
        if end < 0:
            fail('unterminated TDINFO name')
        names.append(data[p:end].decode('latin-1'))
        p = end + 1

    def name(index):
        if index >= len(names):
            fail('invalid TDINFO name index')
        return names[index]

    modules = []
    for i in range(modules_n):
        modules.append({'index': i, 'name': name(struct.unpack_from('<H', data, modules_at + i * 16)[0]),
                        'language': 'unknown', 'ranges': []})
    ranges = []
    scope_segments = {}
    for i in range(segments_n):
        mod, seg, off, length, scope, count = struct.unpack_from('<6H', data, segments_at + i * 16)
        if not 1 <= mod <= modules_n or (count and not 1 <= scope <= scopes_n) or (count and scope - 1 + count > scopes_n):
            fail('invalid TDINFO segment module/scope index')
        address = 0x100 + seg * 16 + off
        if address + length > 0x100 + image_end - header_size:
            fail('TDINFO code range outside MZ image')
        for si in range(scope - 1, scope - 1 + count):
            scope_segments[si] = seg
        r = {'start': address, 'size': length, 'segment': seg}
        modules[mod - 1]['ranges'].append(r)
        ranges.append((seg, off, off + length, mod - 1))

    scope_records = [struct.unpack_from('<6H', data, scopes_at + i * 12) for i in range(scopes_n)]
    symbol_records = [struct.unpack_from('<4HB', data, symbols_at + i * 9) for i in range(symbols_n)]
    type_records = [struct.unpack_from('<BHHBH', data, types_at + i * 8) for i in range(types_n)]
    basic_types = {0: 'void', 4: 'signed char', 5: 'int', 6: 'long', 8: 'unsigned char',
                   9: 'unsigned int', 10: 'unsigned long', 13: 'float', 14: 'real48',
                   15: 'double', 16: 'long double', 40: 'bool'}

    def describe_type(index):
        if not 1 <= index <= types_n:
            return {'index': index, 'name': None, 'size': None}
        kind, ni, size, flags, target = type_records[index - 1]
        # Preserve unhandled type slots (including continuation records) verbatim.
        label = basic_types.get(kind)
        if kind in (21, 22, 24, 25):
            label = {21: 'near pointer', 22: 'far pointer', 24: 'near386 pointer', 25: 'far386 pointer'}[kind]
        return {'index': index, 'kind': kind, 'name': label, 'size': size,
                'name_index': ni, 'flags': flags, 'target_index': target,
                'raw': data[types_at + (index - 1) * 8:types_at + index * 8].hex()}

    def scope_evidence(seg, off, type_index):
        roots = [i for i, r in enumerate(scope_records)
                 if scope_segments.get(i) == seg and r[2] == 0 and r[4] == off and r[5]]
        evidence = {'type_index': type_index, 'parameters': [], 'locals': [],
                    'complete': False, 'reason': 'calling convention and full signature require verification'}
        if type_index and type_records[type_index - 1][0] == 35:
            record = type_records[type_index - 1]
            evidence['function_flags'] = record[3]
            evidence['return_type'] = describe_type(record[4])
        if len(roots) != 1:
            return evidence
        root = roots[0]
        seen_symbols = set()
        for si, record in enumerate(scope_records):
            # Follow parent links with a bound, so corrupt cycles never hang extraction.
            ancestor, visited = si, set()
            while ancestor != root and ancestor not in visited:
                visited.add(ancestor)
                parent = scope_records[ancestor][2]
                if not parent:
                    break
                ancestor = parent - 1
            if ancestor != root:
                continue
            first, count = record[:2]
            for sym_index in range(first - 1, first - 1 + count):
                if sym_index in seen_symbols:
                    continue
                seen_symbols.add(sym_index)
                ni, ti, offset, segment, flags = symbol_records[sym_index]
                if flags & 7 not in (2, 4):
                    continue
                entry = {'name': name(ni), 'type': describe_type(ti), 'scope': si + 1,
                         'storage': 'stack' if flags & 7 == 2 else 'register', 'flags': flags}
                entry['bp_offset' if flags & 7 == 2 else 'register_code'] = (
                    offset - 0x10000 if flags & 7 == 2 and offset >= 0x8000 else offset)
                evidence['parameters' if flags & 8 else 'locals'].append(entry)
        grouped = {}
        for entry in evidence['parameters']:
            key = (entry['name'], entry['type']['index'])
            parameter = grouped.setdefault(key, {'name': entry['name'], 'type': entry['type'], 'locations': []})
            parameter['locations'].append({k: v for k, v in entry.items() if k not in ('name', 'type')})
        evidence['parameters'] = sorted(grouped.values(), key=lambda p: min(
            (loc['bp_offset'] for loc in p['locations'] if loc['storage'] == 'stack'), default=0x10000))
        return evidence

    scopes = {}
    entry_scopes = {}
    for i in range(scopes_n):
        first, count, parent, fn, off, length = struct.unpack_from('<6H', data, scopes_at + i * 12)
        if parent > scopes_n or (fn not in (0xfffe, 0xffff) and fn > symbols_n) or (count and (first < 1 or first - 1 + count > symbols_n)):
            fail('invalid TDINFO scope index')
        if parent == 0 and length and i in scope_segments:
            entry_scopes.setdefault((scope_segments[i], off), []).append((off, length))
        if fn and fn not in (0xfffe, 0xffff):
            scopes.setdefault(fn, []).append((off, length))

    functions, variables, publics = [], [], []
    skipped = 0
    warnings = []
    for i in range(symbols_n):
        ni, ti, off, seg, flags = struct.unpack_from('<4HB', data, symbols_at + i * 9)
        symbol_name = name(ni)
        if ti > types_n:
            fail('invalid TDINFO type index')
        if flags & 7 != 0 or not symbol_name:  # Exclude constants, locals, registers and types.
            skipped += 1
            continue
        type_id = data[types_at + (ti - 1) * 8] if ti else None
        owners = [r for r in ranges if r[0] == seg and r[1] <= off < r[2]]
        module = owners[0][3] if len(owners) == 1 else -1
        is_function = (type_id == 35 and bool(owners)) or i + 1 in scopes or (seg, off) in entry_scopes
        address = 0x100 + seg * 16 + off
        symbol = {'address': address, 'name': symbol_name, 'mangled': symbol_name,
                  'module': module, 'static': None, 'class': None, 'type': None,
                  'segment': seg, 'offset': off}
        publics.append(dict(symbol, size=0))
        if is_function and not 0x100 <= address < 0x100 + image_end - header_size:
            warnings.append('omitted function candidate outside MZ load image: ' + symbol_name)
            skipped += 1
            continue
        if type_id == 35 and not is_function:
            warnings.append('unresolved function-typed symbol outside code ranges: ' + symbol_name)
        if not is_function and (not ti or owners or type_id in (35, 36, 44, 45)):
            skipped += 1  # Preserve unclassified public names without inventing functions.
            continue
        if is_function:
            lengths = [n for o, n in scopes.get(i + 1, []) + entry_scopes.get((seg, off), []) if o == off and n]
            limit = min((r[2] - off for r in owners), default=0)
            size = max(lengths, default=0)
            if size and (not limit or size <= limit):
                if address + size > 0x100 + image_end - header_size:
                    fail('TDINFO function scope outside MZ image')
            else:
                size = 0
            symbol.update(params=None, returns=None, convention='unknown', size=size,
                          size_source='scope' if size else 'unknown', range_end=address + limit)
            symbol['signature_evidence'] = scope_evidence(seg, off, ti)
            functions.append(symbol)
        else:
            variables.append(symbol)
    functions.sort(key=lambda f: f['address'])
    for f in functions:
        if not f['size'] and f['range_end'] > f['address']:
            end = min((g['address'] for g in functions if g['segment'] == f['segment']
                       and f['address'] < g['address'] < f['range_end']), default=f['range_end'])
            f.update(size=end - f['address'], size_source='inferred')
        del f['range_end']
    return {'debug_info': 'Borland TDINFO %d.%02d' % (major, minor), 'languages': [],
            'objects': [], 'modules': modules, 'functions': functions, 'data': variables,
            'symbols': publics, 'skipped_symbols': skipped, 'warnings': warnings,
            'types': [describe_type(i + 1) for i in range(types_n)]}


def apply_signatures(doc, overrides):
    """Apply explicit, complete ABI declarations; never promote debug guesses to callables."""
    if not isinstance(overrides, dict):
        raise DebugInfoError('signatures must be an object keyed by symbol name or 0xADDRESS')
    pending = []
    matched = set()
    for key, sig in overrides.items():
        try:
            address = int(key, 16) if key.lower().startswith('0x') else None
        except ValueError:
            address = None
        matches = [f for f in doc['functions'] if f['mangled'] == key or address == f['address']]
        if len(matches) != 1:
            raise DebugInfoError('signature key must match exactly one function: ' + key)
        if matches[0]['address'] in matched:
            raise DebugInfoError(key + ': duplicate signature for function address')
        matched.add(matches[0]['address'])
        if not isinstance(sig, dict) or sig.get('convention') not in ('cdecl16_near', 'cdecl16_far'):
            raise DebugInfoError(key + ': convention must be cdecl16_near or cdecl16_far')
        params, returns, return_words = sig.get('params'), sig.get('returns'), sig.get('return_words')
        if not isinstance(params, list) or not isinstance(returns, str) or not returns:
            raise DebugInfoError(key + ': explicit params and returns are required')
        if type(return_words) is not int or return_words not in (0, 1, 2) or (returns == 'void') != (return_words == 0):
            raise DebugInfoError(key + ': return_words must be 0 (void), 1 (AX), or 2 (DX:AX)')
        if any(not isinstance(p, dict) or not isinstance(p.get('type'), str) or not p['type'] or
               type(p.get('words')) is not int or p['words'] not in (1, 2) for p in params):
            raise DebugInfoError(key + ': each parameter needs a type and words (1 or 2)')
        if sum(p['words'] for p in params) > 128:
            raise DebugInfoError(key + ': too many parameter words')
        pending.append((matches[0], {k: sig[k] for k in ('convention', 'params', 'returns', 'return_words')}))
    for function, signature in pending:
        function.update(signature)
        function['signature_source'] = 'explicit override'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('exe')
    ap.add_argument('--functions', help='write address,name,size,module CSV')
    ap.add_argument('--symbols', help='write all addressable static/public names, including unclassified labels')
    ap.add_argument('--data', help='write data symbols CSV')
    ap.add_argument('--signatures', help='JSON mapping function names/0xADDRESS to verified 16-bit cdecl signatures')
    ap.add_argument('--json', help='write symbols JSON for gen_decomp.py')
    ap.add_argument('--modules', action='store_true', help='print modules and code ranges')
    args = ap.parse_args()
    try:
        with open(args.exe, 'rb') as file:
            doc = parse(file.read())
        doc['executable'] = os.path.basename(args.exe)
        if args.signatures:
            with open(args.signatures) as file:
                apply_signatures(doc, json.load(file))
        for path, symbols in ((args.functions, doc['functions']), (args.data, doc['data']),
                              (args.symbols, doc['symbols'])):
            if path:
                with open(path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(('address', 'name', 'size', 'module'))
                    for s in symbols:
                        mod = s['module']
                        writer.writerow(('%08x' % s['address'], s['name'], s.get('size', 0),
                                         doc['modules'][mod]['name'] if mod >= 0 else ''))
        if args.json:
            with open(args.json, 'w') as file:
                json.dump(doc, file, indent=2)
                file.write('\n')
    except (OSError, DebugInfoError, json.JSONDecodeError) as exc:
        sys.exit('%s: %s' % (args.exe, exc))
    print('%s: %s, %d functions, %d data symbols, %d skipped symbols' % (
        args.exe, doc['debug_info'], len(doc['functions']), len(doc['data']), doc['skipped_symbols']))
    for warning in doc['warnings']:
        print('warning: ' + warning, file=sys.stderr)
    if args.modules:
        for mod in doc['modules']:
            print('%s: %s' % (mod['name'], ', '.join('%08x+%x' % (r['start'], r['size']) for r in mod['ranges'])))


if __name__ == '__main__':
    main()
