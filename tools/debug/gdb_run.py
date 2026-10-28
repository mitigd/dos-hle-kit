#!/usr/bin/env python3
"""Run a dos-hle-kit game under gdb and print a backtrace when it stops.

    python3 tools/debug/gdb_run.py --exe build/carpet-hle -- --overlay /tmp/carpet-gdb
    python3 tools/debug/gdb_run.py --exe build/duke3d-hle -- --game /path/to/game

Everything after `--` is passed to the game. The script runs in batch mode with symbols and
thread info, ignores the KVM kick signal (SIGUSR1), and on any real stop prints the program
status, registers, and `thread apply all bt full`. The game window stays interactive, so you can
reproduce the crash normally.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--exe", default="build/carpet-hle", help="game executable (default: %(default)s)")
    ap.add_argument("--gdb", default="gdb", help="gdb executable (default: %(default)s)")
    ap.add_argument("args", nargs=argparse.REMAINDER, help="game arguments, after --")
    a = ap.parse_args()

    exe = os.path.abspath(a.exe)
    if not os.path.isfile(exe) or not os.access(exe, os.X_OK):
        sys.exit("not an executable: %s" % exe)
    gdb = shutil.which(a.gdb) or a.gdb
    if not shutil.which(gdb) and not os.path.isfile(gdb):
        sys.exit("gdb not found: %s" % a.gdb)

    game_args = a.args
    if game_args and game_args[0] == "--":
        game_args = game_args[1:]

    commands = """set pagination off
set confirm off
set print thread-events off
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
handle SIGPIPE nostop noprint pass
run
echo \\n=== STOPPED ===\\n
info program
info registers
thread apply all bt full
"""
    with tempfile.NamedTemporaryFile("w", suffix=".gdb", delete=False) as f:
        f.write(commands)
        cmd_file = f.name

    print("gdb: %s" % gdb)
    print("exe: %s" % exe)
    if game_args:
        print("args: %s" % " ".join(game_args))
    print("Click the game window to capture the mouse; Ctrl+G releases.")
    print("A real crash will print a backtrace below.\n")

    try:
        return subprocess.call([gdb, "-q", "-batch", "-x", cmd_file, "--args", exe] + game_args)
    finally:
        os.unlink(cmd_file)


if __name__ == "__main__":
    sys.exit(main())
