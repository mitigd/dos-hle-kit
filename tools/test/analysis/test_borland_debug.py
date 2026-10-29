"""Run with python3 -m unittest discover -s tools/test/analysis."""
import csv
import json
import shutil
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools/analysis'))
from borland_debug import DebugInfoError, apply_signatures, parse


def fixture(padding=0, extension=0, sentinel=0):
    image = bytearray(1024)
    struct.pack_into('<2sHH', image, 0, b'MZ', 0, 2)
    struct.pack_into('<H', image, 8, 4)
    pool = b'First\0Second\0Global\0Local\0src/game.c\0Label\0'
    header = bytearray(48)
    struct.pack_into('<HBBI12H', header, 0, 0x52fb, 16, 3, len(pool),
                     6, 2, 0, 5, 3, 1, 0, 1, 0, 0, 1, 0)
    struct.pack_into('<H', header, 46, extension)
    symbols = b''.join(struct.pack('<4HB', *s) for s in (
        (1, 1, 0x10, 1, 0), (2, 1, 0x20, 1, 0),
        (3, 2, 0x50, 3, 0), (4, 2, 0xfffc, 0, 2), (6, 0, 0x15, 1, 0)))
    module = struct.pack('<H14x', 5)
    scope = struct.pack('<6H', 4, 1, 0, sentinel, 0x10, 8)
    segment = struct.pack('<6H4x', 1, 1, 0x10, 0x30, 1, 1)
    types = struct.pack('<BHHBH', 35, 0, 0, 0, 0) + struct.pack('<BHHBH', 5, 0, 2, 0, 0)
    return bytes(image) + b'\0' * padding + header + b'\0' * extension + symbols + module + scope + segment + types + pool


class BorlandTests(unittest.TestCase):
    def test_addresses_classification_sizes(self):
        for padding, extension, sentinel in ((0, 0, 0), (15, 32, 0xffff), (16, 16, 0xfffe)):
            doc = parse(fixture(padding, extension, sentinel))
            self.assertEqual([(s['name'], s['address'], s['size']) for s in doc['functions']],
                             [('First', 0x120, 8), ('Second', 0x130, 0x20)])
            self.assertEqual([s['size_source'] for s in doc['functions']], ['scope', 'inferred'])
            self.assertEqual([s['name'] for s in doc['data']], ['Global'])
            self.assertEqual([s['name'] for s in doc['symbols']], ['First', 'Second', 'Global', 'Label'])
            self.assertTrue(all(s['convention'] == 'unknown' and s['params'] is None for s in doc['functions']))

    def test_function_type_without_code_range_stays_unclassified(self):
        data = bytearray(fixture())
        # A procedure-typed variable is not necessarily a function entry point.
        struct.pack_into('<H', data, 1024 + 48 + 2 * 9 + 2, 1)
        doc = parse(data)
        self.assertEqual([s['name'] for s in doc['functions']], ['First', 'Second'])
        self.assertIn('Global', [s['name'] for s in doc['symbols']])
        self.assertTrue(doc['warnings'])

    def test_truncated_corrupt_and_other_formats(self):
        data = fixture()
        for truncated in (data[:20], data[:1050], data[:-1], b'no debug'):
            with self.assertRaises(DebugInfoError):
                parse(truncated)
        for offset, value in ((1024 + 4, 0xffffffff), (1024 + 48, 100), (1024 + 50, 100)):
            bad = bytearray(data)
            struct.pack_into('<I' if value == 0xffffffff else '<H', bad, offset, value)
            with self.assertRaises(DebugInfoError):
                parse(bad)
        bad = bytearray(data)
        struct.pack_into('<I', bad, 0x3c, 64)
        bad[64:66] = b'NE'
        with self.assertRaisesRegex(DebugInfoError, 'real-mode'):
            parse(bad)

    def test_parameter_and_return_evidence_does_not_guess_convention(self):
        data = bytearray(fixture())
        pool_size = struct.unpack_from('<I', data, 1024 + 4)[0]
        type_at = len(data) - pool_size - 16
        struct.pack_into('<BHHBH', data, type_at, 35, 0, 0, 4, 2)
        struct.pack_into('<4HB', data, 1024 + 48 + 3 * 9, 4, 2, 6, 0, 10)
        function = parse(data)['functions'][0]
        evidence = function['signature_evidence']
        self.assertEqual(evidence['return_type']['name'], 'int')
        self.assertEqual(evidence['function_flags'], 4)
        self.assertEqual(evidence['parameters'][0]['name'], 'Local')
        self.assertEqual(evidence['parameters'][0]['locations'][0]['bp_offset'], 6)
        self.assertEqual(function['convention'], 'unknown')
        self.assertIsNone(function['params'])

    def test_explicit_signature_validation_is_atomic(self):
        good = {'convention': 'cdecl16_far', 'params': [{'type': 'far pointer', 'words': 2}],
                'returns': 'long', 'return_words': 2}
        for bad in ({}, {**good, 'convention': 'pascal'}, {**good, 'return_words': 3},
                    {**good, 'returns': 'void'}, {**good, 'params': [{'type': 'int', 'words': True}]}):
            doc = parse(fixture())
            with self.assertRaises(DebugInfoError):
                apply_signatures(doc, {'First': good, 'Second': bad})
            self.assertEqual(doc['functions'][0]['convention'], 'unknown')
        doc = parse(fixture())
        apply_signatures(doc, {'0x00000120': good})
        self.assertEqual(doc['functions'][0]['signature_source'], 'explicit override')
        with self.assertRaises(DebugInfoError):
            apply_signatures(doc, {'missing': good})
        with self.assertRaises(DebugInfoError):
            apply_signatures(doc, {'First': good, '0x120': good})

    def test_word_wrappers_native_frames_and_existing_watcom(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            doc = parse(fixture())
            apply_signatures(doc, {
                'First': {'convention': 'cdecl16_far', 'params': [{'type': 'far pointer', 'words': 2}],
                          'returns': 'long', 'return_words': 2},
                'Second': {'convention': 'cdecl16_near', 'params': [{'type': 'int', 'words': 1}],
                           'returns': 'int', 'return_words': 1}})
            watcom = dict(doc['functions'][1], name='Watcom', mangled='Watcom', convention='watcom',
                          params=[{'type': 'int', 'slots': 1}])
            doc['functions'].append(watcom)
            path, out = tmp / 'debug.json', tmp / 'out'
            path.write_text(json.dumps(doc))
            cmd = [sys.executable, str(ROOT / 'tools/decomp/gen_decomp.py'), '--build', 'test=' + str(path), '--out', str(out)]
            subprocess.run(cmd, check=True, capture_output=True)
            guest = (out / 'gen/guest.cpp').read_text()
            self.assertIn('CallGuestFar16', guest)
            self.assertIn('CallGuestNear16(sym::Fn', guest)  # linked address; no double relocation
            self.assertIn('near call requires the original code segment', guest)
            self.assertIn('CallGuestWatcom', guest)
            self.assertIn('CallOriginal', guest)
            for module in (out / 'src').glob('*.cpp'):
                self.fail('unexpected module path')
            module = out / 'game.cpp'
            text = module.read_text().replace('// @decomp First original',
                '// @decomp First native\nuint32_t First(hlekit::Machine&, uint16_t lo, uint16_t hi) { return uint32_t(hi) << 16 | lo; }')
            text = text.replace('// @decomp Second original',
                '// @decomp Second native\nuint32_t Second(hlekit::Machine&, uint16_t a) { return a; }')
            module.write_text(text)
            subprocess.run(cmd, check=True, capture_output=True)
            registry = (out / 'gen/registry.cpp').read_text()
            self.assertIn('Seam::Ret::Far16', registry)
            self.assertIn('Seam::Ret::Near16', registry)
            self.assertIn('m.StackAddr(4)', registry)
            self.assertIn('m.StackAddr(2)', registry)
            self.assertIn('Set16(Reg::Edx', registry)
            compiler = shutil.which('c++')
            if compiler:
                subprocess.run([compiler, '-std=c++20', '-fsyntax-only', '-I' + str(ROOT / 'include'),
                                '-I' + str(out), *map(str, out.rglob('*.cpp'))], check=True, capture_output=True)

    def test_cli_to_generator_and_rerun(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            exe, csv_path, doc, out = [tmp / n for n in ('game.exe', 'functions.csv', 'debug.json', 'decomp')]
            exe.write_bytes(fixture())
            subprocess.run([sys.executable, str(ROOT / 'tools/analysis/borland_debug.py'), str(exe),
                            '--functions', str(csv_path), '--json', str(doc)], check=True, capture_output=True)
            with csv_path.open() as file:
                rows = list(csv.DictReader(file))
            self.assertEqual(int(rows[0]['address'], 16), 0x120)
            self.assertEqual(json.loads(doc.read_text())['functions'][0]['module'], 0)
            cmd = [sys.executable, str(ROOT / 'tools/decomp/gen_decomp.py'), '--build', 'game=' + str(doc), '--out', str(out)]
            subprocess.run(cmd, check=True, capture_output=True)
            self.assertIn('First', (out / 'gen/symbols.h').read_text())
            self.assertNotIn('uint32_t First', (out / 'gen/guest.h').read_text())
            before = {p.relative_to(out): p.read_bytes() for p in out.rglob('*') if p.is_file()}
            subprocess.run(cmd, check=True, capture_output=True)
            self.assertEqual(before, {p.relative_to(out): p.read_bytes() for p in out.rglob('*') if p.is_file()})


if __name__ == '__main__':
    unittest.main()
