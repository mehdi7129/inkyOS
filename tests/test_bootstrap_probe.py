"""Exercise stream boundaries and refusal guards without root or a VM."""
import importlib.util
import multiprocessing
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'bootstrap_probe', Path(__file__).parents[1] / 'scripts/probe-bootstrap-linux.py')
probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)


class BootstrapProbeTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close); self.addCleanup(right.close)
        return left, right

    def test_platform_and_uid_refused_before_builder_access(self):
        for system, uid in (('Darwin', 0), ('Linux', 1000)):
            with self.subTest(system=system, uid=uid), patch.object(probe.platform, 'system', return_value=system), \
                    patch.object(probe.os, 'geteuid', return_value=uid), \
                    patch.object(probe, 'trusted_directory', side_effect=AssertionError('filesystem accessed')):
                with self.assertRaises(probe.ProbeError):
                    probe.check_environment()

    def test_fragmented_stream_waits_for_eof_and_preserves_all_bytes(self):
        left, right = self.pair()
        raw = b'{"operation":"time","unix_seconds":1500}'
        def send():
            for piece in (raw[:1], raw[1:5], raw[5:]):
                right.sendall(piece)
            right.shutdown(socket.SHUT_WR)
        worker = threading.Thread(target=send); worker.start()
        self.assertEqual(probe.read_request(left), raw)
        worker.join(1); self.assertFalse(worker.is_alive())

    def test_exact_limit_accepted_and_extra_byte_refused(self):
        for count, accepted in ((probe.MAX_REQUEST, True), (probe.MAX_REQUEST + 1, False)):
            with self.subTest(count=count):
                left, right = self.pair(); right.sendall(b'x' * count); right.shutdown(socket.SHUT_WR)
                if accepted:
                    self.assertEqual(probe.read_request(left), b'x' * count)
                else:
                    with self.assertRaises(probe.FrameError):
                        probe.read_request(left)

    def test_empty_eof_and_unfinished_request_have_no_complete_frame(self):
        left, right = self.pair(); right.shutdown(socket.SHUT_WR)
        with self.assertRaises(probe.FrameError):
            probe.read_request(left)
        left, right = self.pair(); right.sendall(b'{')
        with patch.object(probe, 'FRAME_TIMEOUT', 0.02), self.assertRaises(probe.FrameError):
            probe.read_request(left)

    @unittest.skipUnless('fork' in multiprocessing.get_all_start_methods(), 'Fork required by Linux fixture')
    def test_idle_server_expires_without_parent_stop_request(self):
        # No client or receipt operation occurs: this exercises the real accept
        # loop with a short internal deadline, without root or Linux-only APIs.
        context = multiprocessing.get_context('fork')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            read, write = context.Pipe(duplex=False)
            stop = context.Event()
            process = context.Process(target=probe.server,
                args=(root / 's', root / 'unused-receipt', write, stop, False),
                kwargs={'_lifetime_seconds': 0.1})
            try:
                process.start(); write.close()
                self.assertTrue(read.poll(3), 'Server did not start')
                self.assertEqual(read.recv(), {'kind': 'ready'})
                process.join(2)
                self.assertFalse(process.is_alive(), 'Server depends on its parent to stop')
                self.assertEqual(process.exitcode, 0)
                self.assertFalse(stop.is_set())
            finally:
                if process.is_alive():
                    process.kill(); process.join(2)
                read.close(); write.close()


if __name__ == '__main__':
    unittest.main()
