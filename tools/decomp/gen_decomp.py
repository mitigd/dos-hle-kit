#!/usr/bin/env python3
"""Lay out (and keep up to date) a project's decompilation tree from the executable's symbols.

    python3 tools/decomp/gen_decomp.py --build lo=docs/debug_lo.json [--build hi=docs/debug_hi.json] \\
        --out src/decompiled --namespace cm

Input: one JSON per executable build, written by `tools/analysis/watcom_debug.py GAME.EXE --json F`
(functions with signatures, data, source modules). Several builds of one program (e.g. a lo-res
and a hi-res EXE) share one tree: functions and globals are paired by mangled name, and the
build is chosen at run time (`<ns>::sym::Select(index)`, builds in command-line order).

Output, under --out:

  <module>.cpp          one file per original source module (image1.cpp, cmfire.cpp, crt/...),
                        one block per function, in address order:

                            // @decomp Image1_Render original
                            // @end

                        A block is yours. Change `original` to `native` and run the generator
                        again: it writes the typed skeleton (calling the original through
                        CallOriginal) and registers it. Bodies and status survive every re-run;
                        functions that disappeared are kept at the end of the file.
  gen/symbols.h/.cpp    every function and global, by name, with its address in each build
  gen/guest.h/.cpp      `guest::Fn(m, args...)` calls the game's function (or its translation,
                        when that is native) and `guest::orig::Fn` always the original code
  gen/registry.cpp      `RegisterDecompiled()`: every `native` block as a seam in area
                        "decomp/<module>" (A/B: `--no-seam decomp/<module>`, `--no-seam NAME`)
  gen/natives.h         prototypes of the native functions
  decomp.h              what a module file includes
  meson.build           `decompiled_src`, every file above

Generated files under gen/, decomp.h and meson.build are rewritten every run; module files are
merged. The project calls `<ns>::sym::Select(build)` and then `<ns>::RegisterDecompiled()` before
`hlekit::Main`.
"""
import argparse
import json
import os
import re
import sys

HEADER_MARK = "// @decomp "
END_MARK = "// @end"


# Names the C/C++ headers may define as macros (or that are keywords): never used bare.
_RESERVED = {"errno", "stdin", "stdout", "stderr", "assert", "environ", "offsetof", "va_start", "va_arg",
             "va_end", "setjmp", "longjmp", "NULL", "EOF", "getc", "putc", "getchar", "putchar", "min", "max",
             "major", "minor", "unix", "linux", "new", "delete", "this", "class", "default", "int", "char",
             "long", "short", "float", "double", "signed", "unsigned", "void", "operator", "main"}


def ident(text):
    t = text.replace("::~", "::dtor_").replace("~", "dtor_")
    t = re.sub(r"[^A-Za-z0-9_]", "_", t.replace("::", "_"))
    t = re.sub(r"_+", "_", t).strip("_")
    if not t or t[0].isdigit():
        t = "f_" + t
    if t in _RESERVED or (t.upper() == t and any(ch.isalpha() for ch in t)):
        t += "_"                                       # macro-shaped (EINVAL, SEEK_SET) or reserved
    return t


def module_path(name):
    """Where a module's file goes: game sources by file name, libraries by their directory,
    assembly and runtime one-function modules under asm/ and crt/."""
    base = name.replace("\\", "/")
    stem = os.path.splitext(os.path.basename(base))[0].lower()
    ext = os.path.splitext(base)[1].lower()
    if ext == ".asm":
        return "asm/%s.cpp" % stem
    if "/" not in base:
        return "crt/%s.cpp" % ident(stem).lower()
    parts = [p for p in base.split("/") if p and not p.endswith(":")]
    lib = [p.lower() for p in parts[:-1] if p.lower() not in ("src", "work", "source")]
    if len(parts) > 1 and lib and lib[-1] not in ("cm",):
        return "%s/%s.cpp" % (ident(lib[-1]).lower(), ident(stem).lower())
    return "%s.cpp" % ident(stem).lower()


class Fn:
    def __init__(self, f):
        self.mangled = f["mangled"]
        self.name = f["name"]
        self.params = f["params"]
        self.returns = f["returns"]
        self.convention = f["convention"]
        self.cls = f["class"]
        self.size = f["size"]
        self.addr = {}
        self.module = None
        self.id = None

    @property
    def method(self):
        return bool(self.cls) and not self.name.startswith("vftable")

    def args(self):
        """[(c name, type text)] as passed: `self` first for methods, a double takes two slots."""
        if self.params is None:
            return None
        out = [("self", self.cls + "*")] if self.method else []
        for i, p in enumerate(self.params):
            if p["type"] == "...":
                return None
            if p["slots"] == 2:
                out += [("a%d_lo" % i, p["type"] + " (low)"), ("a%d_hi" % i, p["type"] + " (high)")]
            elif p["slots"] == 1:
                out.append(("a%d" % i, p["type"]))
        return out

    def callable(self):
        return self.convention in ("watcom", "cdecl") and self.args() is not None

    def returns_value(self):
        return self.returns not in (None, "void")


def load(builds):
    """Pair functions and data of all builds by mangled name; the first build orders the files."""
    fns, data, order = {}, {}, []
    for bi, (_, path) in enumerate(builds):
        doc = json.load(open(path))
        mods = doc["modules"]
        for f in doc["functions"]:
            if f["convention"] == "unknown" and f["mangled"].startswith("W?$Wvt"):
                continue
            fn = fns.get(f["mangled"])
            if fn is None:
                fn = fns[f["mangled"]] = Fn(f)
                fn.module = mods[f["module"]]["name"] if 0 <= f["module"] < len(mods) else "unknown"
                order.append(fn)
            fn.addr[bi] = f["address"]
        for d in doc["data"]:
            ent = data.setdefault(d["mangled"], {"name": d["name"], "type": d["type"], "addr": {}})
            ent["addr"][bi] = d["address"]
    order.sort(key=lambda f: f.addr.get(0, 1 << 32))
    seen = {}
    for fn in order:
        base = ident(fn.name)
        n = seen.get(base, 0)
        seen[base] = n + 1
        fn.id = base if n == 0 else "%s_%d" % (base, n + 1)
    dseen, dlist = {}, []
    for m, d in sorted(data.items(), key=lambda kv: min(kv[1]["addr"].values())):
        if not d["name"] or d["name"].startswith("W?$"):
            continue
        base = ident(d["name"])
        n = dseen.get(base, 0)
        dseen[base] = n + 1
        d["id"] = base if n == 0 else "%s_%d" % (base, n + 1)
        dlist.append(d)
    return order, dlist


def signature_comment(fn):
    if fn.params is None:
        return "%s  (%s, signature unknown)" % (fn.name, fn.convention)
    args = ", ".join(p["type"] for p in fn.params)
    return "%s(%s) -> %s  [%s]" % (fn.name, args, fn.returns, fn.convention)


def cparams(fn):
    return "".join(", uint32_t %s" % n for n, _ in fn.args())


def write_if_changed(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and open(path).read() == text:
        return False
    open(path, "w").write(text)
    return True


FUNCTIONS_MARK = "// @functions"


def parse_module_file(path):
    """{id: [status, body lines]} and the file's preamble (everything before // @functions)."""
    blocks, preamble, cur, in_pre = {}, [], None, True
    if not os.path.exists(path):
        return blocks, None
    for line in open(path).read().split("\n"):
        if in_pre:
            if line.startswith(FUNCTIONS_MARK):
                in_pre = False
            else:
                preamble.append(line)
            continue
        if line.startswith(HEADER_MARK):
            parts = line[len(HEADER_MARK):].split()
            cur = parts[0]
            blocks[cur] = [parts[1] if len(parts) > 1 else "original", []]
        elif cur is not None:
            if line.startswith(END_MARK):
                cur = None
            else:
                blocks[cur][1].append(line)
    return blocks, (preamble if not in_pre else None)


def skeleton(fn, ns):
    ret = "uint32_t" if fn.returns_value() else "void"
    names = ", ".join(n for n, _ in fn.args())
    call = "guest::orig::%s(m%s)" % (fn.id, (", " + names) if names else "")
    lines = ["%s %s(hlekit::Machine& m%s) {" % (ret, fn.id, cparams(fn))]
    for n, t in fn.args():
        lines.append("    // %s: %s" % (n, t))
    lines.append("    %s%s;   // TODO: translate; until then the original runs" % ("return " if ret != "void" else "", call))
    lines.append("}")
    return lines


def module_file(fn_list, path, rel, ns, builds):
    blocks, preamble = parse_module_file(path)
    out = preamble if preamble is not None else [
        "// %s" % (fn_list[0].module if fn_list else rel),
        "//",
        "// Translated from the original module. One block per original function, in address order:",
        "// `original` - the game's code runs; `native` - the body replaces it. After changing a status,",
        "// re-run tools/decomp/gen_decomp.py (it writes the skeleton and registers the function).",
        '#include "%sdecomp.h"' % ("../" * rel.count("/")),
        "",
        "namespace %s {" % ns,
        "",
    ]
    out.append(FUNCTIONS_MARK)
    natives, used = [], set()
    for fn in fn_list:
        status, body = blocks.get(fn.id, ["original", []])
        used.add(fn.id)
        addrs = "  ".join("%s %08x" % (b[0], fn.addr[i]) for i, b in enumerate(builds) if i in fn.addr)
        out.append("")
        out.append("// " + "-" * 96)
        out.append("// " + signature_comment(fn))
        out.append("// %s  size %d  %s" % (addrs, fn.size, fn.mangled))
        out.append("%s%s %s" % (HEADER_MARK, fn.id, status))
        has_code = any(l.strip() for l in body)
        if status == "native":
            if not fn.callable():
                body = ["#error %s: calling convention or signature unknown - translate by hand" % fn.id] + body
            elif not has_code:
                body = skeleton(fn, ns)
            natives.append(fn)
        out.extend(body if (has_code or status == "native") else [])
        out.append(END_MARK)
    orphans = [(k, v) for k, v in blocks.items() if k not in used and (v[0] == "native" or any(l.strip() for l in v[1]))]
    if orphans:
        out.append("")
        out.append("// Blocks whose function is no longer in the symbols (kept, not registered):")
        for k, (status, body) in orphans:
            out.append("%s%s orphan" % (HEADER_MARK, k))
            out.extend(body)
            out.append(END_MARK)
    out += ["", "}  // namespace %s" % ns, ""]
    return "\n".join(out), natives


def main():
    ap = argparse.ArgumentParser(description="decompilation tree from symbols")
    ap.add_argument("--build", action="append", required=True, help="NAME=debug.json (repeat; first orders the files)")
    ap.add_argument("--out", required=True, help="the tree, e.g. src/decompiled")
    ap.add_argument("--namespace", default="game")
    a = ap.parse_args()
    builds = [tuple(b.split("=", 1)) for b in a.build]
    ns = a.namespace
    fns, data = load(builds)

    by_file = {}
    for fn in fns:
        by_file.setdefault(module_path(fn.module), []).append(fn)

    natives_all, files = [], []
    for rel, lst in sorted(by_file.items()):
        path = os.path.join(a.out, rel)
        text, natives = module_file(lst, path, rel, ns, builds)
        write_if_changed(path, text)
        natives_all += [(rel, n) for n in natives]
        files.append(rel)

    nb = len(builds)
    # gen/symbols.h/.cpp
    h = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.", "#pragma once", "", "#include <cstdint>", "",
         "namespace %s::sym {" % ns, "",
         "// Builds, in generator order: %s" % ", ".join("%d %s" % (i, b[0]) for i, b in enumerate(builds)),
         "void Select(int build);", "int Selected();",
         "uint32_t Fn(int id);     // linked (decompiler) address in the selected build, 0 = not in it",
         "uint32_t Data(int id);", "", "namespace fn {", "enum : int {"]
    h += ["    %s,   // %s" % (f.id, f.name) for f in fns]
    h += ["    kCount", "};", "}  // namespace fn", "", "namespace data {", "enum : int {"]
    h += ["    %s,   // %s" % (d["id"], d["type"] or "") for d in data]
    h += ["    kCount", "};", "}  // namespace data", "", "}  // namespace %s::sym" % ns, ""]
    c = ['// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.', '#include "symbols.h"', "",
         "namespace %s::sym {" % ns, "namespace {", "", "int selected = 0;", "",
         "const uint32_t kFn[][%d] = {" % nb]
    c += ["    {%s},   // %s" % (", ".join("0x%08x" % f.addr.get(i, 0) for i in range(nb)), f.id) for f in fns]
    c += ["};", "", "const uint32_t kData[][%d] = {" % nb]
    c += ["    {%s},   // %s" % (", ".join("0x%08x" % d["addr"].get(i, 0) for i in range(nb)), d["id"]) for d in data]
    c += ["    {%s}," % ", ".join(["0"] * nb)] if not data else []
    c += ["};", "", "}  // namespace", "",
          "void Select(int build) { selected = build >= 0 && build < %d ? build : 0; }" % nb,
          "int Selected() { return selected; }",
          "uint32_t Fn(int id) { return id >= 0 && id < fn::kCount ? kFn[id][selected] : 0; }",
          "uint32_t Data(int id) { return id >= 0 && id < data::kCount ? kData[id][selected] : 0; }", "",
          "}  // namespace %s::sym" % ns, ""]
    write_if_changed(os.path.join(a.out, "gen/symbols.h"), "\n".join(h))
    write_if_changed(os.path.join(a.out, "gen/symbols.cpp"), "\n".join(c))

    # gen/guest.h/.cpp
    gh = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.",
          "// guest::F(m, ...) calls the game's F (its translation when that is native); guest::orig::F the original code.",
          "#pragma once", "", '#include "hlekit/machine.h"', "", "#include <cstdint>", "", "namespace %s::guest {" % ns, ""]
    gc = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.", '#include "guest.h"', '#include "symbols.h"', "",
          "namespace %s::guest {" % ns, ""]
    origs = []
    for f in fns:
        if not f.callable():
            continue
        ret = "uint32_t"
        names = ", ".join(n for n, _ in f.args())
        gh.append("%s %s(hlekit::Machine& m%s);" % (ret, f.id, cparams(f)))
        if f.convention == "cdecl":
            body = "return m.CallGuestCdecl(m.Data(sym::Fn(sym::fn::%s)), {%s});" % (f.id, names)
        else:
            body = "return m.CallGuestWatcom(m.Data(sym::Fn(sym::fn::%s)), {%s});" % (f.id, names)
        gc.append("%s %s(hlekit::Machine& m%s) { %s }" % (ret, f.id, cparams(f), body))
        if f.convention == "watcom":
            origs.append(f)
    gh += ["", "namespace orig {"]
    gh += ["uint32_t %s(hlekit::Machine& m%s);" % (f.id, cparams(f)) for f in origs]
    gh += ["}  // namespace orig", "", "}  // namespace %s::guest" % ns, ""]
    gc += ["", "namespace orig {"]
    gc += ["uint32_t %s(hlekit::Machine& m%s) { return m.CallOriginal(m.Data(sym::Fn(sym::fn::%s)), {%s}); }"
           % (f.id, cparams(f), f.id, ", ".join(n for n, _ in f.args())) for f in origs]
    gc += ["}  // namespace orig", "", "}  // namespace %s::guest" % ns, ""]
    write_if_changed(os.path.join(a.out, "gen/guest.h"), "\n".join(gh))
    write_if_changed(os.path.join(a.out, "gen/guest.cpp"), "\n".join(gc))

    # gen/natives.h, gen/registry.cpp
    nh = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.", "#pragma once", "",
          '#include "hlekit/machine.h"', "", "#include <cstdint>", "", "namespace %s {" % ns, ""]
    rc = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.", '#include "hlekit/decomp.h"',
          '#include "natives.h"', '#include "symbols.h"', "", "namespace %s {" % ns, "",
          "// The `native` blocks of the module files, as seams at their address in the selected build.",
          "void RegisterDecompiled() {", "    using hlekit::Reg;"]
    for rel, f in natives_all:
        if not f.callable():
            continue
        ret = "uint32_t" if f.returns_value() else "void"
        nh.append("%s %s(hlekit::Machine& m%s);   // %s" % (ret, f.id, cparams(f), rel))
        n = len(f.args())
        args = ", ".join("m.WatcomArg(%d)" % i if f.convention == "watcom" else "m.Arg(%d)" % i for i in range(n))
        call = "%s(m%s)" % (f.id, (", " + args) if args else "")
        body = "m.vm.Set(Reg::Eax, %s);" % call if ret != "void" else "%s;" % call
        pop = 4 * max(0, n - 4) if f.convention == "watcom" else 0
        rc.append("    if (uint32_t a = sym::Fn(sym::fn::%s))" % f.id)
        rc.append('        hlekit::Decompiled().push_back({a, "%s", "decomp/%s", "%s",' % (
            f.name, os.path.splitext(rel)[0], f.mangled.replace("\\", "\\\\").replace('"', '\\"')))
        rc.append("            [](hlekit::Machine& m) { %s }, %d});" % (body, pop))
    nh += ["", "void RegisterDecompiled();", "", "}  // namespace %s" % ns, ""]
    rc += ["}", "", "}  // namespace %s" % ns, ""]
    write_if_changed(os.path.join(a.out, "gen/natives.h"), "\n".join(nh))
    write_if_changed(os.path.join(a.out, "gen/registry.cpp"), "\n".join(rc))

    # decomp.h, meson.build
    dh = ["// Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit. What every module file includes.",
          "#pragma once", "", '#include "gen/guest.h"', '#include "gen/natives.h"', '#include "gen/symbols.h"',
          '#include "hlekit/machine.h"', "", "#include <cstdint>", "", "namespace %s {" % ns, "",
          "// A global of the game by symbol: its guest address in the selected build.",
          "inline uint32_t Global(hlekit::Machine& m, int id) { return m.Data(sym::Data(id)); }", "",
          "}  // namespace %s" % ns, ""]
    write_if_changed(os.path.join(a.out, "decomp.h"), "\n".join(dh))
    srcs = ["gen/symbols.cpp", "gen/guest.cpp", "gen/registry.cpp"] + files
    mb = ["# Generated by dos-hle-kit tools/decomp/gen_decomp.py - do not edit.",
          "decompiled_src = files(", "\n".join("  '%s'," % s for s in srcs), ")",
          "decompiled_inc = include_directories('.', 'gen')", ""]
    write_if_changed(os.path.join(a.out, "meson.build"), "\n".join(mb))
    print("%d functions in %d files, %d globals, %d native" % (len(fns), len(files), len(data), len(natives_all)))


if __name__ == "__main__":
    sys.exit(main())
