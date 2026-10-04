#!/usr/bin/python3 -I
"""Fixed SSH command dispatcher. No shell, alternate root or runtime test mode."""
import sys
sys.dont_write_bytecode = True

import json
import os
import select
import selectors
import subprocess
import time


RUNNER = "/usr/local/lib/inkyos-test-ssh/runner"
LIMIT = 4096
INPUT_TIMEOUT = 5.0
RUNNER_TIMEOUT = 35.0
OUTPUT_LIMIT = 32768
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
VERBS = ("preflight", "activate", "stop", "status")


def operation(command):
    if type(command) is not str or command not in VERBS:
        raise ValueError("invalid_request")
    return command


def request(raw, verb):
    operation(verb)
    if type(raw) is not bytes or not 0 < len(raw) <= LIMIT:
        raise ValueError("invalid_request")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("invalid_request")
            value[key] = item
        return value
    def invalid(_value):
        raise ValueError("invalid_request")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_float=invalid, parse_constant=invalid)
    fields = {"schema_version"}
    reference = {"utc_reference", "utc_reference_age", "utc_reference_source"}
    allowed = ([fields, fields | reference] if verb == "preflight" else
               [fields, fields | reference | {"confirm_test_refresh"}] if verb == "activate" else [fields])
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1
            or set(value) not in allowed
            or ("confirm_test_refresh" in value and value["confirm_test_refresh"] is not True)):
        raise ValueError("invalid_request")
    if reference <= set(value):
        if (type(value["utc_reference"]) is not int or not 1767225600 <= value["utc_reference"] <= 2524608000
                or type(value["utc_reference_age"]) is not int or not 0 <= value["utc_reference_age"] <= 60
                or type(value["utc_reference_source"]) is not str
                or value["utc_reference_source"] not in {"independent-device", "gnss"}):
            raise ValueError("invalid_request")
    return value


def receive(fd, *, clock=time.monotonic, wait=select.select, read=os.read):
    deadline, raw = clock() + INPUT_TIMEOUT, bytearray()
    while True:
        remaining = deadline - clock()
        if remaining <= 0 or not wait([fd], [], [], remaining)[0]:
            raise ValueError("input_timeout")
        chunk = read(fd, min(1024, LIMIT + 1 - len(raw)))
        if not chunk:
            return bytes(raw)
        raw.extend(chunk)
        if len(raw) > LIMIT:
            raise ValueError("invalid_request")


def invoke(payload):
    """Bound both stdin delivery and stdout; timeout is not job cancellation."""
    child = None
    selector = selectors.DefaultSelector()
    try:
        child = subprocess.Popen(("/usr/bin/sudo", "-n", "--", RUNNER), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV, cwd="/", close_fds=True)
        for stream, event in ((child.stdin, selectors.EVENT_WRITE), (child.stdout, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event)
        deadline, offset, output = time.monotonic() + RUNNER_TIMEOUT, 0, bytearray()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("runner_timeout")
            for key, event in selector.select(remaining):
                if event & selectors.EVENT_WRITE:
                    count = os.write(key.fd, payload[offset:])
                    if count <= 0:
                        raise ValueError("runner_unavailable")
                    offset += count
                    if offset == len(payload):
                        selector.unregister(key.fileobj)
                        child.stdin.close()
                else:
                    block = os.read(key.fd, min(4096, OUTPUT_LIMIT + 1 - len(output)))
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(block)
                        if len(output) > OUTPUT_LIMIT:
                            raise ValueError("runner_unavailable")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("runner_timeout")
        return child.wait(timeout=remaining), bytes(output)
    finally:
        selector.close()
        if child is not None:
            if child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    # A privileged sudo monitor or an exit race may refuse the
                    # signal. Still close descriptors; do not claim job cancel.
                    pass
                try:
                    child.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
            for stream in (child.stdin, child.stdout):
                stream.close()


def dispatch(command, raw, *, invoke=invoke):
    try:
        verb = operation(command)
        envelope = {"schema_version": 1, "operation": verb, "request": request(raw, verb)}
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        if len(payload) > LIMIT:
            raise ValueError("invalid_request")
        code, output = invoke(payload)
        if type(code) is not int or code not in {0, 1, 64} or type(output) is not bytes or len(output) > OUTPUT_LIMIT:
            raise ValueError("runner_unavailable")
        return code, output
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, subprocess.SubprocessError):
        return 64, b""


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        return 64
    try:
        verb = operation(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
        code, output = dispatch(verb, receive(0))
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return code
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return 64


if __name__ == "__main__":
    sys.exit(main())
