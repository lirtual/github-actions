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
