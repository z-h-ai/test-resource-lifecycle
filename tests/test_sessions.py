import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from trl.core import process_birth, stable_host_id, sweep_ledgers
from trl.session import open_session, close_session, status_session


class Sessions(unittest.TestCase):
    def test_parallel_close_and_readonly_observation_after_command_timeout(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / 'state'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-test', 'profiles': {'e2e': {
                'timeout_seconds': 1, 'resources': {'filesystem': [{'name': 'data', 'path': '.tmp/${TRL_RUN_ID}'}]}}}}
            end = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
            a = open_session(config, 'e2e', root, 'a', owner, end, state)
            b = open_session(config, 'e2e', root, 'b', owner, end, state)
            before = Path(a['context']).read_bytes()
            class Future(datetime):
                @classmethod
                def now(cls, tz=None):
                    return datetime.now(tz) + timedelta(hours=2)
            with patch('trl.session.datetime', Future):
                self.assertEqual(status_session(a['context'], state)['status'], 'open')
            self.assertEqual(Path(a['context']).read_bytes(), before)
            private = Path(a['environment_file'])
            self.assertEqual(private.stat().st_mode & 0o777, 0o600)
            self.assertEqual(close_session(a['context'], owner, state_root=state)[0], 0)
            self.assertFalse(private.exists())
            self.assertEqual(status_session(a['context'], state)['status'], 'closed')
            self.assertEqual(close_session(a['context'], owner, state_root=state)[0], 0)
            self.assertTrue((root / '.tmp/b').exists())
            self.assertEqual(status_session(b['context'], state)['status'], 'open')
            self.assertEqual(close_session(b['context'], owner, state_root=state)[0], 0)
            self.assertFalse((root / '.tmp/a').exists())
            self.assertFalse((root / '.tmp/b').exists())

    def test_unknown_identity_and_wrong_owner_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-test', 'profiles': {'e2e': {'resources': {}}}}
            end = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
            with self.assertRaises(ValueError):
                open_session(config, 'e2e', root, 'unknown', {**owner, 'process_birth': 'unknown'}, end, state)
            a = open_session(config, 'e2e', root, 'a', owner, end, state)
            with self.assertRaises(ValueError):
                close_session(a['context'], {**owner, 'pid': 1}, state_root=state)
            self.assertTrue(Path(a['environment_file']).exists())
            close_session(a['context'], owner, state_root=state)

    def test_crashed_owner_recovers_through_existing_sweeper(self):
        import subprocess, sys
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
            owner = dict(pid=process.pid, process_birth=process_birth(process.pid), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-crash', 'profiles': {'e2e': {'resources': {
                'filesystem': [{'name': 'data', 'path': '.tmp/${TRL_RUN_ID}'}]}}}}
            try:
                opened = open_session(config, 'e2e', root, 'crash', owner,
                    (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
            finally:
                process.kill(); process.wait()
            outcome = sweep_ledgers(repository_id='session-crash', all_repos=False, immediate=True, state_root=state)
            self.assertEqual(outcome[0]['result'], 'swept')
            self.assertFalse((root / '.tmp/crash').exists())
            self.assertFalse(Path(opened['environment_file']).exists())

    def test_cleanup_uses_recovered_credentials_without_argv_secrets(self):
        import subprocess
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            (root / 'cleanup.sql').write_text('SELECT 1;')
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-sql', 'profiles': {'e2e': {'resources': {
                'sql_file': [{'name': 'cleanup', 'file': 'cleanup.sql', 'database_url_env': 'SESSION_TEST_DB'}]}}}}
            with patch.dict(os.environ, {'SESSION_TEST_DB': 'postgresql://tester:private-value@127.0.0.1:5432/test?options=-c%20search_path%3Dfixture'}):
                opened = open_session(config, 'e2e', root, 'sql', owner,
                    (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
            def fake(argv, **kwargs):
                self.assertNotIn('private-value', str(argv))
                self.assertIn('options=-c%20search_path%3Dfixture', argv[2])
                self.assertEqual(kwargs['env']['PGPASSWORD'], 'private-value')
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch('trl.session.command', side_effect=fake) as run:
                self.assertEqual(close_session(opened['context'], owner, state_root=state)[0], 0)
                self.assertEqual(run.call_count, 1)

    def test_hostless_sql_uri_and_inherited_libpq_environment_survive_recovery(self):
        import subprocess
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            (root / 'cleanup.sql').write_text('SELECT 1;')
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-hostless', 'profiles': {'e2e': {'resources': {
                'sql_file': [{'name': 'cleanup', 'file': 'cleanup.sql', 'database_url_env': 'SESSION_TEST_DB'}]}}}}
            uri = 'postgresql:///test?host=%2Ftmp&options=-c%20search_path%3Dfixture'
            with patch.dict(os.environ, {'SESSION_TEST_DB': uri, 'PGPASSWORD': 'private-value', 'PGSSLMODE': 'verify-full'}):
                opened = open_session(config, 'e2e', root, 'hostless', owner,
                    (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
            def fake(argv, **kwargs):
                self.assertEqual(argv[2], uri)
                self.assertEqual(kwargs['env']['PGPASSWORD'], 'private-value')
                self.assertEqual(kwargs['env']['PGSSLMODE'], 'verify-full')
                return subprocess.CompletedProcess(argv, 0, '', '')
            with patch('trl.session.command', side_effect=fake):
                self.assertEqual(close_session(opened['context'], owner, state_root=state)[0], 0)

    def test_failed_prepare_preserves_recovery_configuration(self):
        from trl.core import Lifecycle
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-prepare', 'profiles': {'e2e': {'resources': {
                'services': [{'name': 'broken', 'argv': ['/does-not-exist']} ]}}}}
            with self.assertRaises(OSError):
                open_session(config, 'e2e', root, 'prepare', owner,
                    (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
            private = list(state.glob('test-resource-lifecycle/runs/*/*/*/session-private.json'))
            self.assertEqual(len(private), 1)
            context = private[0].parent / 'run-context.json'
            self.assertEqual(close_session(context, owner, state_root=state)[0], 0)

    def test_cli_service_does_not_hold_open_response_pipe(self):
        import subprocess, sys
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            config = {'policy_version': 1, 'repository_id': 'session-service', 'profiles': {'e2e': {'resources': {
                'services': [{'name': 'app', 'argv': [sys.executable, '-c', 'import time; print("ready", flush=True); time.sleep(60)']}]}}}}
            config_path = root / 'config.json'; config_path.write_text(json.dumps(config))
            env = {**os.environ, 'XDG_STATE_HOME': str(state)}
            result = subprocess.run([sys.executable, '-m', 'trl', 'session', 'open', '--config', str(config_path),
                '--profile', 'e2e', '--attempt', 'service', '--owner-pid', str(os.getpid()), '--deadline-at',
                (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            opened = json.loads(result.stdout)
            owner = opened['owner']
            self.assertEqual(close_session(opened['context'], owner, state_root=state)[0], 0)

    def test_service_cannot_execute_before_durable_claim(self):
        from trl.core import Lifecycle
        import sys
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'; marker = root / 'ran'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'claim-failure', 'profiles': {'e2e': {'resources': {
                'services': [{'name': 'app', 'argv': [sys.executable, '-c', f'from pathlib import Path; Path({str(marker)!r}).touch()']}]}}}}
            with patch.object(Lifecycle, 'add_resource', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    open_session(config, 'e2e', root, 'claim', owner,
                        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
            self.assertFalse(marker.exists())

    def test_close_serializes_with_preparation(self):
        import threading
        from trl.core import Lifecycle
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'; receipt = root / 'receipt.json'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-race', 'profiles': {'e2e': {'resources': {
                'filesystem': [{'name': 'data', 'path': '.tmp/${TRL_RUN_ID}'}]}}}}
            entered = threading.Event(); release = threading.Event(); closed = threading.Event(); errors = []
            original = Lifecycle._filesystem_path
            def pause(lifecycle, path):
                entered.set(); release.wait(5)
                return original(lifecycle, path)
            def opening():
                try:
                    open_session(config, 'e2e', root, 'race', owner,
                        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state, receipt)
                except Exception as error: errors.append(error)
            def closing():
                try: close_session(json.loads(receipt.read_text())['context'], owner, state_root=state)
                except Exception as error: errors.append(error)
                finally: closed.set()
            with patch.object(Lifecycle, '_filesystem_path', pause):
                opener = threading.Thread(target=opening); opener.start()
                self.assertTrue(entered.wait(5))
                closer = threading.Thread(target=closing); closer.start()
                self.assertFalse(closed.wait(.1))
                release.set(); opener.join(5); closer.join(5)
            self.assertFalse(errors, errors)
            self.assertTrue(closed.is_set())
            self.assertFalse((root / '.tmp/race').exists())
            self.assertEqual(status_session(json.loads(receipt.read_text())['context'], state)['status'], 'closed')

    @unittest.skipUnless(os.environ.get('TRL_DOCKER_INTEGRATION') == '1', 'requires Docker')
    def test_two_postgresql_sessions_preserve_peer_database_and_accounts(self):
        import subprocess
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw); state = root / 'state'
            owner = dict(pid=os.getpid(), process_birth=process_birth(os.getpid()), host_id=stable_host_id(state))
            config = {'policy_version': 1, 'repository_id': 'session-db', 'profiles': {'e2e': {'timeout_seconds': 1,
                'resources': {'postgresql': [{'name': 'db', 'image': 'postgres:16-alpine', 'database': 'acceptance',
                    'username': 'trl', 'password_env': 'TRL_TEST_POSTGRES_PASSWORD', 'inject_url_env': 'DATABASE_URL'}]}}}}
            sessions = []
            def sql(session, statement):
                ledger = json.loads((Path(session['context']).parent / 'resource-ledger.json').read_text())
                container = next(x['id'] for x in ledger['resources'] if x['kind'] == 'container')
                return subprocess.check_output(['docker', 'exec', container, 'psql', '-U', 'trl', '-d', 'acceptance', '-tAc', statement], text=True).strip()
            try:
                for name in ('a', 'b'):
                    session = open_session(config, 'e2e', root, name, owner,
                        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(), state)
                    sessions.append(session)
                    sql(session, "CREATE TABLE actors (name text); INSERT INTO actors VALUES ('" + name + "');")
                values = [json.loads(Path(s['environment_file']).read_text())['environment']['DATABASE_URL'] for s in sessions]
                self.assertNotEqual(values[0], values[1])
                self.assertEqual(sql(sessions[0], 'SELECT name FROM actors'), 'a')
                self.assertEqual(sql(sessions[1], 'SELECT name FROM actors'), 'b')
                self.assertEqual(close_session(sessions[0]['context'], owner, state_root=state)[0], 0)
                self.assertEqual(sql(sessions[1], 'SELECT name FROM actors'), 'b')
            finally:
                for session in sessions:
                    close_session(session['context'], owner, state_root=state)

if __name__ == '__main__': unittest.main()
