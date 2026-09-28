import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import uuid

spec = importlib.util.spec_from_file_location(
    'initialization_receipt', Path(__file__).parents[1] / 'scripts/initialization-receipt.py')
receipt = importlib.util.module_from_spec(spec); spec.loader.exec_module(receipt)


def begin_worker(path, intent, owner, barrier, queue):
    barrier.wait()
    try:
        queue.put(receipt.begin(path, intent, **owner))
    except receipt.ReceiptError as exc:
        queue.put({'error': type(exc).__name__})


def crash_worker(path, intent, owner, point):
    original_replace = receipt.os.replace
    original_fsync = receipt.os.fsync
    replaces = 0; syncs = 0
    def replace(*args, **kwargs):
        nonlocal replaces
        replaces += 1
        original_replace(*args, **kwargs)
        if point == f'replace-{replaces}':
            os._exit(71)
    def fsync(fd):
        nonlocal syncs
        syncs += 1
        original_fsync(fd)
        if point == f'fsync-{syncs}':
            os._exit(72)
    with patch.object(receipt.os, 'replace', replace), patch.object(receipt.os, 'fsync', fsync):
        receipt.begin(path, intent, **owner)
    os._exit(0)


class InitializationReceiptTests(unittest.TestCase):
    def setUp(self):
        # The model rejects world-writable ancestors, including /tmp. Fixture
        # owner overrides permit a private directory beneath the test user's home.
        temporary = tempfile.TemporaryDirectory(prefix='.inkyos-receipt-test-', dir=Path.home().resolve())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.root.chmod(0o700)
        self.path = self.root / 'authorization'
        self.owner = {'_owner_uid': os.geteuid(), '_owner_gid': os.getegid()}
        self.intent = '12345678-1234-4234-8234-123456789abc'

    def create(self):
        return receipt.create_authorization(self.path, **self.owner)

    def begin(self, intent=None):
        return receipt.begin(self.path, intent or self.intent, **self.owner)

    def inspect(self):
        return receipt.inspect(self.path, **self.owner)

    def test_explicit_create_consume_same_intent_retry_and_other_intent_refused(self):
        self.assertEqual(self.create(), {'status': 'authorized'})
        self.assertEqual(self.inspect(), {'status': 'authorized'})
        first = self.begin(); again = self.begin()
        self.assertEqual(first['status'], 'newly_consumed')
        self.assertEqual(again, {**first, 'status': 'already_consumed'})
        self.assertEqual(str(uuid.UUID(first['receipt']['receipt_id'])), first['receipt']['receipt_id'])
        self.assertRegex(first['receipt']['digest'], r'^[0-9a-f]{64}$')
        self.assertEqual(self.inspect(), {**first, 'status': 'consumed'})
        with self.assertRaises(receipt.IntentConflict):
            self.begin(str(uuid.uuid4()))

    def test_absent_state_or_empty_existing_directory_never_authorizes(self):
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        self.assertFalse(self.path.exists())
        self.path.mkdir(mode=0o700)
        with self.assertRaises(receipt.RecoveryRequired):
            self.create()
        with self.assertRaises(receipt.RecoveryRequired):
            self.inspect()
        self.assertEqual(list(self.path.iterdir()), [])

    def test_consumed_before_missing_db_crash_never_recreates_authorization(self):
        self.create(); first = self.begin()
        # No app store was created. Its absence is not an input to this model.
        again = self.begin()
        self.assertEqual(again['status'], 'already_consumed')
        self.assertEqual(again['receipt'], first['receipt'])
        with self.assertRaises(receipt.RecoveryRequired):
            self.create()

    def test_missing_or_corrupt_consumption_requires_recovery(self):
        self.create(); self.begin(); consumption = self.path / 'consumption.json'
        original = consumption.read_bytes()
        for replacement in (None, b'{}\n', b'{"state": "consumed", "state": "authorized"}\n'):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    consumption.unlink()
                else:
                    consumption.write_bytes(replacement); consumption.chmod(0o600)
                with self.assertRaises(receipt.RecoveryRequired):
                    self.begin()
                if not consumption.exists():
                    consumption.touch(mode=0o600)
                consumption.write_bytes(original)

    def test_lost_or_corrupt_main_record_is_never_reissued(self):
        self.create(); self.begin(); state = self.path / 'state.json'
        state.unlink()
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        state.write_text('broken'); state.chmod(0o600)
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()

    def test_noncanonical_intent_rejected_without_state_change(self):
        self.create(); before = (self.path / 'state.json').read_bytes()
        for intent in (self.intent.upper(), self.intent.replace('-', ''), '{' + self.intent + '}', '', None):
            with self.subTest(intent=intent), self.assertRaises(receipt.ReceiptError):
                receipt.begin(self.path, intent, **self.owner)
        self.assertEqual((self.path / 'state.json').read_bytes(), before)
        self.assertEqual(set(path.name for path in self.path.iterdir()), {'state.json', 'lock'})

    def test_inspect_has_no_write_or_create_operations(self):
        self.create(); self.begin()
        original_open = receipt.os.open
        def readonly_open(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            return original_open(path, flags, *args, **kwargs)
        with patch.object(receipt.os, 'open', readonly_open), \
                patch.object(receipt.os, 'replace', side_effect=AssertionError('write')), \
                patch.object(receipt.os, 'fsync', side_effect=AssertionError('write')):
            self.assertEqual(self.inspect()['status'], 'consumed')

    def test_links_special_files_and_unsafe_parents_fail_closed(self):
        self.create(); lock = self.path / 'lock'; lock.unlink()
        outside = self.root / 'outside'; outside.write_bytes(b''); outside.chmod(0o600)
        lock.symlink_to(outside)
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        lock.unlink(); os.link(outside, lock)
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        lock.unlink(); os.mkfifo(lock, 0o600)
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        link = self.root / 'linked-parent'; link.symlink_to(self.path)
        with self.assertRaises((OSError, receipt.ReceiptError)):
            receipt.create_authorization(link / 'nested', **self.owner)
        self.root.chmod(0o777)
        with self.assertRaises(receipt.ReceiptError):
            self.inspect()
        self.root.chmod(0o700)

    def test_record_modes_and_binding_are_checked(self):
        self.create(); self.begin(); state = self.path / 'state.json'
        state.chmod(0o644)
        with self.assertRaises(receipt.RecoveryRequired):
            self.inspect()
        state.chmod(0o600)
        value = json.loads(state.read_text()); value['receipt']['digest'] = '0' * 64
        state.write_text(json.dumps(value))
        with self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)

    def concurrent(self, intents):
        self.create(); context = multiprocessing.get_context('fork')
        barrier = context.Barrier(2); queue = context.Queue()
        workers = [context.Process(target=begin_worker, args=(self.path, intent, self.owner, barrier, queue))
                   for intent in intents]
        for worker in workers:
            worker.start()
        results = [queue.get(timeout=10) for _ in workers]
        for worker in workers:
            worker.join(10)
            if worker.is_alive():
                worker.kill(); worker.join()
            self.assertEqual(worker.exitcode, 0)
        queue.close(); queue.join_thread()
        return results

    def test_two_simultaneous_same_intent_begins_issue_one_grant(self):
        results = self.concurrent([self.intent, self.intent])
        self.assertEqual(sorted(result['status'] for result in results), ['already_consumed', 'newly_consumed'])
        self.assertEqual(results[0]['receipt'], results[1]['receipt'])

    def test_two_simultaneous_different_intents_allow_only_one(self):
        results = self.concurrent([self.intent, str(uuid.uuid4())])
        self.assertEqual(sum(result.get('status') == 'newly_consumed' for result in results), 1)
        self.assertEqual(sum(result.get('error') == 'IntentConflict' for result in results), 1)

    def test_process_crashes_at_each_write_boundary_never_reissue_grant(self):
        # Every point occurs after bytes have been written. Actual power-loss
        # durability remains a filesystem/hardware qualification concern.
        context = multiprocessing.get_context('fork')
        for point in ('fsync-1', 'replace-1', 'fsync-2', 'fsync-3', 'replace-2', 'fsync-4'):
            with self.subTest(point=point):
                self.path = self.root / point; self.create()
                worker = context.Process(target=crash_worker,
                                         args=(self.path, self.intent, self.owner, point))
                worker.start(); worker.join(10)
                if worker.is_alive():
                    worker.kill(); worker.join()
                self.assertIn(worker.exitcode, (71, 72))
                try:
                    result = self.begin()
                except receipt.RecoveryRequired:
                    pass
                else:
                    self.assertEqual(result['status'], 'already_consumed')

    def test_fsync_error_after_terminal_replace_returns_recovery_then_consumed(self):
        self.create(); original = receipt.os.fsync; calls = 0
        def fail_last(fd):
            nonlocal calls
            calls += 1
            if calls == 4:
                raise OSError('injected directory sync failure')
            return original(fd)
        with patch.object(receipt.os, 'fsync', fail_last), self.assertRaises(receipt.RecoveryRequired):
            self.begin()
        self.assertEqual(self.begin()['status'], 'already_consumed')


if __name__ == '__main__':
    unittest.main()
