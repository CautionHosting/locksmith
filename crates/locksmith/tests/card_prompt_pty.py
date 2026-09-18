#!/usr/bin/env python3
"""Run the ignored Rust PIN driver in a real PTY; no smartcard required."""
import errno
import os
import pty
import select
import signal
import sys
import termios
import time

binary = os.path.abspath(sys.argv[1])
for typed, expected in [(b"654321\n", b"PIN accepted"), (b"654\x03", b"Cancelled"),
                         (b"1\n2\n3\n", b"Validation attempts exhausted")]:
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(binary, [binary, "openpgp::card_prompt::tests::inline_pin_terminal_driver",
                            "--exact", "--ignored", "--nocapture"])
    original = termios.tcgetattr(fd)
    output = bytearray()
    sent = False
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 8192)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
            # Wait until echo is disabled, not merely until the prompt was printed.
            if not sent and b"PIN: " in output and not termios.tcgetattr(fd)[3] & termios.ECHO:
                os.write(fd, typed)
                sent = True
        else:
            raise AssertionError("PIN driver timed out")
        restored = termios.tcgetattr(fd)
        _, status = os.waitpid(pid, 0)
        pid = None
        assert os.waitstatus_to_exitcode(status) == 0, output
        assert sent and expected in output, output
        if expected == b"Validation attempts exhausted":
            assert output.count(b"PIN: ") == 3, output
        assert b"Existing release summary" in output, output
        assert b"654" not in output, "PIN input was echoed"
        assert b"\x1b" not in output, "terminal clearing/control escape emitted"
        mask = termios.ECHO | termios.ICANON | termios.ISIG
        assert original[3] & mask == restored[3] & mask, "terminal input flags not restored"
        print(expected.decode() + ": hidden input, retained output, restored terminal verified")
    finally:
        if pid is not None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(fd)
