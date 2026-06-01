#!/usr/bin/env python3
"""
Wrapper that tees stdin, stdout, and stderr of cvc5 to the tty.
Intended to help with debugging test cases by inspecting the exact input and
output of cvc5.

cvc5's stdout is forwarded directly to the terminal. The contents of its stderr
are printed in red.  Input lines sent to cvc5 are prefixed with `cvc5>` as if
running interactively.

Usage: cvc5_tee.py [--strip-args] [--solver-args=ARGS] <command> [args...]

Options:
  --strip-args          Strip all arguments passed to cvc5 by the caller.
  --solver-args=ARGS    Additional arguments to pass to the solver
                        (space-separated). Can be combined with --strip-args
                        to fully control the solver command line.
  --z3                  Shorthand for: CVC5=z3 ./cvc5_tee.py --strip-args --solver-args="-in"

Example:
  $ ./cvc5_tee.py cargo test symcc::solver::test::get_model_sat
  running 1 test
  cvc5> (set-option :produce-models true)
  cvc5> (assert true)
  cvc5> (check-sat)
  <stdin>:2.2: No set-logic command was given before this point.
  <stdin>:2.2: cvc5 will make all theories available.
  sat
  cvc5> (get-model)
  (
  )
  test symcc::solver::test::get_model_sat ... ok
"""

import os
import sys
import subprocess
import select
import shutil
from typing import Dict, IO, NoReturn
from abc import ABC, abstractmethod


class StreamHandler(ABC):
    def __init__(self, src_fd: int) -> None:
        self.src_fd = src_fd

    @abstractmethod
    def on_data(self, chunk: bytes) -> bool: ...

    @abstractmethod
    def on_eof(self) -> None: ...


class StdinHandler(StreamHandler):
    """Reads our stdin, forwards to child's stdin pipe, tees lines to tty with a `cvc5>` prompt."""

    def __init__(self, src_fd: int, pipe: IO[bytes], tty_fd: int, prompt: bytes = b"cvc5> ") -> None:
        super().__init__(src_fd)
        self._pipe = pipe
        self.tty_fd = tty_fd
        self.prompt = prompt
        self._buf = b""
        self._at_line_start = True

    def on_data(self, chunk: bytes) -> bool:
        try:
            os.write(self._pipe.fileno(), chunk)
        except OSError:
            return False
        self._buf += chunk
        while b"\n" in self._buf:
            idx = self._buf.index(b"\n")
            line = self._buf[:idx]
            self._buf = self._buf[idx + 1:]
            prefix = self.prompt if self._at_line_start else b""
            os.write(self.tty_fd, prefix + line + b"\n")
            self._at_line_start = True
        return True

    def on_eof(self) -> None:
        if self._buf:
            prefix = self.prompt if self._at_line_start else b""
            os.write(self.tty_fd, prefix + self._buf)
        self._pipe.close()


class StdoutHandler(StreamHandler):
    """Reads child's stdout, forwards to our stdout, tees verbatim to tty."""

    def __init__(self, src_fd: int, pipe: IO[bytes], dst_fd: int, tty_fd: int) -> None:
        super().__init__(src_fd)
        self._pipe = pipe
        self.dst_fd = dst_fd
        self.tty_fd = tty_fd

    def on_data(self, chunk: bytes) -> bool:
        os.write(self.dst_fd, chunk)
        os.write(self.tty_fd, chunk)
        return True

    def on_eof(self) -> None:
        self._pipe.close()


class StderrHandler(StreamHandler):
    """Reads child's stderr, forwards to our stderr, tees to tty in red."""

    RED = b"\033[31m"
    RESET = b"\033[0m"

    def __init__(self, src_fd: int, pipe: IO[bytes], dst_fd: int, tty_fd: int, use_color: bool) -> None:
        super().__init__(src_fd)
        self._pipe = pipe
        self.dst_fd = dst_fd
        self.tty_fd = tty_fd
        self.use_color = use_color

    def on_data(self, chunk: bytes) -> bool:
        os.write(self.dst_fd, chunk)
        if self.use_color:
            os.write(self.tty_fd, self.RED + chunk + self.RESET)
        else:
            os.write(self.tty_fd, chunk)
        return True

    def on_eof(self) -> None:
        self._pipe.close()


def tty_supports_color(tty_fd: int) -> bool:
    try:
        if not os.isatty(tty_fd):
            return False
    except OSError:
        return False
    term = os.environ.get("TERM", "")
    return term != "" and term != "dumb"


def find_tty() -> str:
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            return os.ttyname(stream.fileno())
        except OSError:
            pass
    return os.ctermid()


def run_inner(tty_path: str, cvc5_cmd: str, strip_args: bool, solver_args: str) -> NoReturn:
    tty_fd: int = os.open(tty_path, os.O_WRONLY)

    use_color: bool = tty_supports_color(tty_fd)

    extra = solver_args.split() if solver_args else []
    cmd = [cvc5_cmd] + extra if strip_args else [cvc5_cmd] + extra + sys.argv[1:]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    stdin_handler = StdinHandler(sys.stdin.fileno(), proc.stdin, tty_fd)
    stdout_handler = StdoutHandler(proc.stdout.fileno(), proc.stdout, sys.stdout.fileno(), tty_fd)
    stderr_handler = StderrHandler(proc.stderr.fileno(), proc.stderr, sys.stderr.fileno(), tty_fd, use_color)

    handlers: Dict[int, StreamHandler] = {
        stdin_handler.src_fd: stdin_handler,
        stdout_handler.src_fd: stdout_handler,
        stderr_handler.src_fd: stderr_handler,
    }

    while handlers:
        readable, _, _ = select.select(list(handlers.keys()), [], [])
        for fd in readable:
            handler = handlers[fd]
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                del handlers[fd]
                handler.on_eof()
                continue

            if not chunk:
                del handlers[fd]
                handler.on_eof()
                continue

            if not handler.on_data(chunk):
                del handlers[fd]
                handler.on_eof()

    os.close(tty_fd)
    sys.exit(proc.wait())


def run_outer() -> NoReturn:
    strip_args = False
    solver_args = ""
    args = sys.argv[1:]

    while args:
        if args[0] == "--strip-args":
            strip_args = True
            args = args[1:]
        elif args[0].startswith("--solver-args="):
            solver_args = args[0][len("--solver-args="):]
            args = args[1:]
        elif args[0] == "--z3":
            strip_args = True
            solver_args = "-in"
            os.environ["CVC5"] = "z3"
            args = args[1:]
        else:
            break

    if not args:
        print(f"Usage: {sys.argv[0]} [--strip-args] [--solver-args=ARGS] <command> [args...]", file=sys.stderr)
        sys.exit(1)

    tty_path: str = find_tty()
    script_path: str = os.path.realpath(__file__)
    cvc5_orig: str = os.environ.get("CVC5", shutil.which("cvc5") or "cvc5")

    env: Dict[str, str] = os.environ.copy()
    env["__CVC5_TEE_WRAPPER"] = "1"
    env["__CVC5_TTY"] = tty_path
    env["__CVC5_ORIG"] = cvc5_orig
    env["CVC5"] = script_path
    if strip_args:
        env["__CVC5_STRIP_ARGS"] = "1"
    if solver_args:
        env["__CVC5_SOLVER_ARGS"] = solver_args

    result: subprocess.CompletedProcess[bytes] = subprocess.run(args, env=env)
    sys.exit(result.returncode)


def main() -> None:
    if os.environ.get("__CVC5_TEE_WRAPPER") == "1":
        tty_path: str = os.environ["__CVC5_TTY"]
        cvc5_cmd: str = os.environ.get("__CVC5_ORIG", "cvc5")
        strip_args: bool = os.environ.get("__CVC5_STRIP_ARGS") == "1"
        solver_args: str = os.environ.get("__CVC5_SOLVER_ARGS", "")
        run_inner(tty_path, cvc5_cmd, strip_args, solver_args)
    else:
        run_outer()


if __name__ == "__main__":
    main()
