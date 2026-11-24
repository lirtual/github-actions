"""Contract tests for bounded Ubuntu Session idle return, without real SSH or RCA."""
import importlib.util
import os
from pathlib import Path
import unittest
import sys
from unittest import mock

PATH=Path(__file__).resolve().parents[1]/'.github/scripts/session_idle.py'
SPEC=importlib.util.spec_from_file_location('session_idle',PATH)
assert SPEC and SPEC.loader
idle=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(idle)

class Clock:
    def __init__(self, now=0): self.now=now
    def time(self): return self.now
    def sleep(self, seconds): self.now+=seconds

@unittest.skipUnless(sys.platform == "linux", "Ubuntu Runner idle policy only")
class SessionIdleTests(unittest.TestCase):
    def test_idle_setting_defaults_to_30_and_rejects_invalid_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(idle.idle_timeout_ms(), 30 * 60 * 1000)
        for value, minutes in (("1", 1), ("5", 5), ("30", 30), ("300", 300)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"SESSION_IDLE_MINUTES": value}):
                self.assertEqual(idle.idle_timeout_ms(), minutes * 60 * 1000)
        for value in ("", "0", "301", "-5", "5.5", "none", " 30", "9999"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {"SESSION_IDLE_MINUTES": value}):
                with self.assertRaises(ValueError):
                    idle.idle_timeout_ms()

    def test_custom_idle_window_and_absolute_deadline(self):
        clock = Clock(1000)
        with mock.patch.dict(os.environ, {"SESSION_IDLE_MINUTES": "5"}), \
             mock.patch.object(idle.time, 'time', clock.time), mock.patch.object(idle.time, 'sleep', clock.sleep), \
             mock.patch.object(idle, 'read_agent', return_value={'state': 'idle', 'last_activity_ms': None}), \
             mock.patch.object(idle, 'ssh_state', return_value='clear'), \
             mock.patch.object(idle, 'prepare_idle_stop', return_value=True) as stopping:
            self.assertEqual(idle.hold_until(1000 + 1200, 1000 * 1000), 'idle')
            self.assertGreaterEqual(clock.now, 1300)
            self.assertLess(clock.now, 1310)
            stopping.assert_called_once()
        clock = Clock(1000)
        with mock.patch.dict(os.environ, {"SESSION_IDLE_MINUTES": "60"}), \
             mock.patch.object(idle.time, 'time', clock.time), mock.patch.object(idle.time, 'sleep', clock.sleep), \
             mock.patch.object(idle, 'read_agent', return_value={'state': 'idle', 'last_activity_ms': None}), \
             mock.patch.object(idle, 'ssh_state', return_value='clear'), \
             mock.patch.object(idle, 'prepare_idle_stop') as stopping:
            self.assertEqual(idle.hold_until(1000 + 1200, 1000 * 1000), 'deadline')
            stopping.assert_not_called()

    def test_idle_exit_after_thirty_minutes_not_before(self):
        clock=Clock(1000)
        with mock.patch.object(idle.time,'time',clock.time), mock.patch.object(idle.time,'sleep',clock.sleep), \
             mock.patch.object(idle,'read_agent',return_value={'state':'idle','last_activity_ms':None}), \
             mock.patch.object(idle,'ssh_state',return_value='clear'), \
             mock.patch.object(idle,'prepare_idle_stop',return_value=True) as stopping:
            self.assertEqual(idle.hold_until(1000+300*60,1000*1000), 'idle')
            self.assertGreaterEqual(clock.now,1000+1800)
            self.assertLess(clock.now,1000+1810)
            stopping.assert_called_once()
    def test_real_activity_resets_window_but_not_job_deadline(self):
        clock=Clock(1000)
        with mock.patch.object(idle.time,'time',clock.time), mock.patch.object(idle.time,'sleep',clock.sleep), \
             mock.patch.object(idle,'read_agent',side_effect=lambda:{'state':'idle','last_activity_ms':1010*1000 if clock.now>=1010 else None}), \
             mock.patch.object(idle,'ssh_state',return_value='clear'), \
             mock.patch.object(idle,'prepare_idle_stop',return_value=True):
            self.assertEqual(idle.hold_until(1000+2000,1000*1000),'idle')
            self.assertGreaterEqual(clock.now,1010+1800)
    def test_unknown_agent_never_causes_early_stop(self):
        clock=Clock(1000)
        with mock.patch.object(idle.time,'time',clock.time), mock.patch.object(idle.time,'sleep',clock.sleep), \
             mock.patch.object(idle,'read_agent',return_value=None), \
             mock.patch.object(idle,'ssh_state',return_value='clear'), \
             mock.patch.object(idle,'prepare_idle_stop') as stopping:
            self.assertEqual(idle.hold_until(1020,1000*1000),'deadline')
            stopping.assert_not_called()
    def test_authenticated_ssh_resets_window_after_disconnect(self):
        clock=Clock(1000)
        with mock.patch.object(idle.time,'time',clock.time), mock.patch.object(idle.time,'sleep',clock.sleep), \
             mock.patch.object(idle,'read_agent',return_value={'state':'idle','last_activity_ms':None}), \
             mock.patch.object(idle,'ssh_state',side_effect=lambda:'busy' if clock.now<1600 else 'clear'), \
             mock.patch.object(idle,'prepare_idle_stop',return_value=True):
            self.assertEqual(idle.hold_until(5000,1000*1000),'idle')
            self.assertGreaterEqual(clock.now,1600+1800-10)
    def test_freeze_rechecks_and_releases_on_ssh_reauthentication(self):
        observed=[]
        with mock.patch.object(idle,'exchange',side_effect=lambda cmd:observed.append(cmd) or ('ready' if cmd=='idle-freeze' else 'released')), \
             mock.patch.object(idle,'read_agent',return_value={'state':'idle','last_activity_ms':None}), \
             mock.patch.object(idle,'stop_ssh_ingress',return_value=True), \
             mock.patch.object(idle,'restore_ssh_ingress') as restore, \
             mock.patch.object(idle,'ssh_state',return_value='busy'):
            self.assertFalse(idle.prepare_idle_stop(1000,2000000,False))
            self.assertIn('release',observed)
            restore.assert_called_once()

    def test_ssh_session_classification_including_no_tty_and_unauthenticated(self):
        import getpass
        user=getpass.getuser()
        for args,expected,final in [
            (f"runner sshd sshd: {user}@notty", "busy",False),
            (f"runner sshd sshd: {user}@pts/0", "busy",True),
            ("root sshd sshd: [accepted]", "clear",False),
            ("root sshd sshd: [accepted]", "unknown",True),
            ("root sshd /usr/sbin/sshd -D", "clear",False),
            ("runner sleep sleep 30", "clear",True),
        ]:
            with self.subTest(args=args,final=final),mock.patch.object(idle.subprocess,'run',
                return_value=mock.Mock(stdout=args)),mock.patch.object(idle.getpass,'getuser',return_value=user):
                self.assertEqual(idle.ssh_state(final),expected)

    def test_agent_snapshot_identity_age_and_permissions_are_not_guessed(self):
        import json,os
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            settings={'GITHUB_ACTIONS':'true','RUNNER_ENVIRONMENT':'github-hosted',
                      'GITHUB_WORKFLOW':'ubuntu','GITHUB_REPOSITORY':'autoactions/github-actions',
                      'ATTEMPT_ID':'11111111-1111-4111-8111-111111111111',
                      'GITHUB_RUN_ID':'100','GITHUB_RUN_ATTEMPT':'1','RUNNER_TEMP':tmp}
            now=1700000000000
            valid={'attempt_id':settings['ATTEMPT_ID'],'github_run_id':100,'github_run_attempt':1,
                   'observed_at_ms':now,'last_activity_ms':None,'state':'idle'}
            with mock.patch.dict(os.environ,settings,clear=True),mock.patch.object(idle.time,'time',return_value=now/1000):
                for payload,expected in [(valid,True),({**valid,'github_run_id':101},False),
                                         ({**valid,'observed_at_ms':now-60000},False),
                                         ({**valid,'last_activity_ms':now+40000},False),
                                         ({**valid,'state':'unexpected'},False)]:
                    with self.subTest(payload=payload),mock.patch.object(idle,'exchange',return_value=json.dumps(payload)):
                        self.assertEqual(idle.read_agent() is not None,expected)
                marker=Path(tmp)/'session-rca-known-failed'
                marker.write_bytes(b'failed\n')
                marker.chmod(0o600)
                os.environ['SESSION_RCA_OUTCOME']='failure'
                self.assertTrue(idle.known_bootstrap_failure())
                marker.chmod(0o644)
                self.assertFalse(idle.known_bootstrap_failure())

    def test_ssh_shutdown_requires_non_killing_systemd_configuration(self):
        with mock.patch.object(idle.subprocess,'run',return_value=mock.Mock(stdout='control-group\n')), \
             mock.patch.object(idle,'systemctl') as systemctl:
            self.assertFalse(idle.stop_ssh_ingress())
            systemctl.assert_not_called()
        with mock.patch.object(idle.subprocess,'run',side_effect=[
                mock.Mock(stdout='process\n'),mock.Mock(stdout='')]), \
             mock.patch.object(idle,'systemctl') as systemctl:
            self.assertTrue(idle.stop_ssh_ingress())
            systemctl.assert_called_once_with('stop','ssh.socket','ssh.service')

    def test_cancelled_idle_stop_reports_both_failed_recoveries(self):
        observed = []
        def exchange(command):
            observed.append(command)
            return "ready" if command == "idle-freeze" else None
        with mock.patch.object(idle, "exchange", side_effect=exchange), \
             mock.patch.object(idle, "read_agent", return_value={"state": "idle", "last_activity_ms": None}), \
             mock.patch.object(idle, "stop_ssh_ingress", return_value=False), \
             mock.patch.object(idle, "restore_ssh_ingress", return_value=False) as restore:
            with self.assertRaisesRegex(RuntimeError, "SSH.*RCA"):
                idle.prepare_idle_stop(1000, 2000000, False)
            restore.assert_called_once()
            self.assertIn("release", observed)

    def test_recovery_failure_never_retries_idle_or_ends_active_hold_early(self):
        clock = Clock(1000)
        with mock.patch.dict(os.environ, {"SESSION_IDLE_MINUTES": "1"}), \
             mock.patch.object(idle.time, "time", clock.time), mock.patch.object(idle.time, "sleep", clock.sleep), \
             mock.patch.object(idle, "read_agent", return_value={"state": "idle", "last_activity_ms": None}), \
             mock.patch.object(idle, "ssh_state", return_value="clear"), \
             mock.patch.object(idle, "exchange", side_effect=lambda cmd: "ready" if cmd == "idle-freeze" else None), \
             mock.patch.object(idle, "restore_ssh_ingress", return_value=False), \
             mock.patch.object(idle, "stop_ssh_ingress", return_value=False) as stopping:
            with self.assertRaisesRegex(RuntimeError, "SSH.*RCA"):
                idle.hold_until(1120, 1000 * 1000)
            self.assertEqual(clock.now, 1120)
            stopping.assert_called_once()

    def test_ssh_restore_requires_exact_tailnet_listener(self):
        for listener, expected in (
            ("LISTEN 0 128 100.64.0.7:22 0.0.0.0:*\n", True),
            ("LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", False),
            ("", False),
        ):
            with self.subTest(listener=listener), mock.patch.object(idle, "systemctl"), \
                 mock.patch.object(idle.subprocess, "run", side_effect=[
                     mock.Mock(stdout="100.64.0.7\n"), mock.Mock(stdout=listener)]):
                self.assertEqual(idle.restore_ssh_ingress(), expected)

    def test_real_private_socket_lost_freeze_ack_is_released(self):
        import socket
        import tempfile
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "session-rca"
            root.mkdir(mode=0o700)
            path = root / "upgrade.sock"
            observed = []
            frozen = []
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                path.chmod(0o600)
                server.listen(2)
                server.settimeout(3)
                def accept():
                    try:
                        for _ in range(2):
                            conn, _ = server.accept()
                            with conn:
                                conn.settimeout(1)
                                with conn.makefile("rb") as wire:
                                    command = wire.readline(128)
                                observed.append(command)
                                if command == b"idle-freeze\n":
                                    frozen.append(True)
                                    # Close without replying after applying the freeze.
                                elif command == b"release\n":
                                    frozen.clear()
                                    conn.sendall(b"released\n")
                    except OSError:
                        pass
                thread = threading.Thread(target=accept, daemon=True)
                thread.start()
                try:
                    with mock.patch.dict(os.environ, {"RUNNER_TEMP": tmp}), \
                         mock.patch.object(idle, "reviewed_runner", return_value=True), \
                         mock.patch.object(idle, "stop_ssh_ingress") as stopping:
                        self.assertFalse(idle.prepare_idle_stop(1000, 2000000, False))
                        stopping.assert_not_called()
                finally:
                    thread.join(4)
                self.assertEqual(observed, [b"idle-freeze\n", b"release\n"])
                self.assertFalse(frozen)

    def test_definite_busy_does_not_release_a_freeze_it_never_acquired(self):
        with mock.patch.object(idle, "exchange", return_value="busy") as exchange, \
             mock.patch.object(idle, "stop_ssh_ingress") as stop:
            self.assertFalse(idle.prepare_idle_stop(1000, 2000000, False))
            exchange.assert_called_once_with("idle-freeze")
            stop.assert_not_called()

    def test_ssh_recovery_exception_does_not_skip_rca_release(self):
        with mock.patch.object(idle, "exchange", side_effect=lambda cmd: "ready" if cmd == "idle-freeze" else "released") as exchange, \
             mock.patch.object(idle, "read_agent", return_value={"state": "idle", "last_activity_ms": None}), \
             mock.patch.object(idle, "stop_ssh_ingress", return_value=False), \
             mock.patch.object(idle, "restore_ssh_ingress", side_effect=RuntimeError("private detail")):
            with self.assertRaisesRegex(RuntimeError, "^SSH$"):
                idle.prepare_idle_stop(1000, 2000000, False)
            exchange.assert_called_with("release")
