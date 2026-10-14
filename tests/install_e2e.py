"""Installer failure injection: real pip-less venv, isolated data, mocked systemd.

Never installs system units or invokes real swanctl/systemctl.
"""
from __future__ import annotations
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'deploy'))
import service_tools as svc


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='install-regression-')
        self.base = Path(self.temp.name) / 'ca app(1) & 100%'
        self.base.mkdir()
        shutil.copytree(ROOT / 'deploy', self.base / 'deploy')
        shutil.copy2(ROOT / 'requirements.txt', self.base / 'requirements.txt')
        self.data = self.base / 'data'
        self.data.mkdir()
        self.marker = self.data / 'keep.txt'
        self.marker.write_text('keep existing data')
        self.env = dict(os.environ, PIP_NO_INDEX='1', PIP_DISABLE_PIP_VERSION_CHECK='1',
                        CA_DATA_DIR=str(self.data), CA_HOST='127.0.0.1', CA_PORT='9443',
                        CA_MANAGE_STRONGSWAN='0')
        self.env.pop('CA_SERVICE_USER', None)

    def tearDown(self):
        self.assertEqual(self.marker.read_text(), 'keep existing data')
        self.temp.cleanup()

    def install(self, *args):
        return subprocess.run(['bash', str(self.base / 'deploy/install.sh'), *args],
                              cwd=self.base, env=self.env, capture_output=True,
                              text=True, timeout=60)

    def test_missing_flag_value_fails_before_initialization(self):
        result = self.install('--port')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('缺少参数值', result.stderr)
        self.assertFalse((self.base / '.venv').exists())

    def test_invalid_port_fails_before_initialization(self):
        result = self.install('--port', '65536')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.base / '.venv').exists())

    def test_reject_plain_http_index(self):
        result = self.install('--pip-index-url', 'http://example.test/simple')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HTTPS', result.stderr)

    def test_system_service_rejects_download_location(self):
        result = self.install('--systemd')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue('/opt/ca-dev' in result.stderr or 'sudo' in result.stderr)
        self.assertFalse((self.base / '.venv').exists())

    def test_unprivileged_mode_requires_explicit_account(self):
        result = self.install('--systemd-unprivileged')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--user', result.stderr)

    def test_root_mode_does_not_enable_duplicate_timer(self):
        result = self.install('--systemd', '--with-timer')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('不需要', result.stderr)

    def test_dry_run_has_no_file_changes(self):
        before = {str(p.relative_to(self.base)): p.read_bytes()
                  for p in self.base.rglob('*') if p.is_file()}
        result = self.install('--dry-run', '--pip-mirror', 'tsinghua')
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {str(p.relative_to(self.base)): p.read_bytes()
                 for p in self.base.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_incomplete_venv_reports_actionable_error(self):
        (self.base / '.venv').mkdir()
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('改名备份', result.stderr)

    def test_real_missing_pip_recovery_then_dependency_failure_is_visible(self):
        subprocess.run([sys.executable, '-m', 'venv', '--without-pip',
                        str(self.base / '.venv')], check=True, capture_output=True)
        result = self.install('--pip-mirror', 'tsinghua')
        self.assertNotEqual(result.returncode, 0)  # no wheels/index: intentional failure
        self.assertIn('ensurepip', result.stdout)
        self.assertIn('依赖安装失败', result.stderr)
        self.assertNotIn('安装成功', result.stdout)
        self.assertFalse((self.data / 'ca.db').exists())
        subprocess.run([str(self.base / '.venv/bin/python'), '-m', 'pip', '--version'],
                       check=True, capture_output=True)
        self.assertIn('https://pypi.tuna.tsinghua.edu.cn/simple',
                      (self.base / '.venv/pip.conf').read_text())

    def test_unit_render_handles_percent_space_quotes_and_dollar(self):
        base = '/opt/ca (1) & 100% $HOME "quote"'
        text = svc.render(ROOT / 'deploy/ca-admin-root.service', base, base + '/data',
                          '127.0.0.1', '9443', 'root')
        self.assertIn('100%%', text)
        self.assertIn('$$HOME', next(s for s in text.splitlines() if s.startswith('ExecStart=')))
        self.assertNotIn('__BASE_DIR__', text)
        self.assertNotIn('/home/*', text)
        self.assertNotIn('BindPaths=', text)

    def test_working_directory_is_absolute_without_wrapping_quotes(self):
        for name in ('ca-admin-root.service', 'ca-admin.service', 'ca-admin-user.service'):
            with self.subTest(template=name):
                text = svc.render(ROOT / 'deploy' / name, '/opt/ca-dev', '/opt/ca-dev/data',
                                  '127.0.0.1', '9443', 'root')
                line = next(line for line in text.splitlines() if line.startswith('WorkingDirectory='))
                self.assertEqual(line, 'WorkingDirectory=/opt/ca-dev')

    def test_single_paths_preserve_literal_characters_without_word_escaping(self):
        base = '/opt/a b "literal" 100% \\dir'
        text = svc.render(ROOT / 'deploy/ca-admin-root.service', base, base + '/data',
                          '127.0.0.1', '9443', 'root')
        value = next(line.split('=', 1)[1] for line in text.splitlines()
                     if line.startswith('WorkingDirectory='))
        self.assertEqual(value, base.replace('%', '%%'))
        self.assertTrue(value.startswith('/'))
        # Environment/ExecStart/ReadWritePaths DO use word parsing; keep quoting there.
        self.assertIn('Environment="CA_DATA_DIR=', text)
        self.assertIn('ExecStart="', text)
        self.assertIn('ReadWritePaths="', text)

    def test_path_watch_uses_unquoted_single_absolute_path(self):
        text = svc.render(ROOT / 'deploy/ca-strongswan-sync.path', '/opt/ca-dev',
                          '/opt/ca-dev/data', '127.0.0.1', '9443', 'root')
        self.assertIn('PathChanged=/opt/ca-dev/data/publish\n', text)
        self.assertNotIn('PathChanged="', text)

    def test_sync_render_does_not_expand_shell_input(self):
        base = str(self.base / '$(touch INJECTED)')
        text = svc.render(ROOT / 'deploy/ca-strongswan-sync.sh', base, base + '/data',
                          '127.0.0.1', '9443', 'root')
        subprocess.run(['bash', '-n'], input=text, text=True, check=True)
        assignments = '\n'.join(line for line in text.splitlines()
                                if line.startswith(('STAGING=', 'BASE_DIR=', 'PY=')))
        result = subprocess.run(['bash'], input=assignments + '\nprintf "%s" "$BASE_DIR"\n',
                                cwd=self.base, capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, base)
        self.assertFalse((self.base / 'INJECTED').exists())

    def test_validation_rejects_unit_injection_and_dangerous_data(self):
        for base, data in [('/opt/app\nUser=bad', '/opt/app/data'), ('/opt/app', '/opt')]:
            with self.assertRaises(ValueError):
                svc.validate(base, data, '127.0.0.1', '9443', 'root')


class ReadinessTests(unittest.TestCase):
    def run_ready(self, state, body, *, timeout=0.05, stable=0):
        result = subprocess.CompletedProcess([], 0, state)
        response = io.StringIO(json.dumps(body))
        response.status = 200
        with patch.object(svc.subprocess, 'run', return_value=result), \
             patch.object(svc.urllib.request, 'build_opener') as opener, \
             contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            opener.return_value.open.return_value = response
            return svc.wait_ready('127.0.0.1', '9443', timeout=timeout, stable_seconds=stable)

    def test_226_namespace_autorestart_is_failure(self):
        self.assertFalse(self.run_ready('ActiveState=activating\nSubState=auto-restart\nExecMainStatus=226\n', {}))

    def test_active_without_correct_http_health_is_failure(self):
        self.assertFalse(self.run_ready('ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=0\n', {'wrong': True}))

    def test_http_ok_without_service_pid_is_failure(self):
        self.assertFalse(self.run_ready('ActiveState=active\nSubState=running\nMainPID=0\n', {'status': 'ok'}))

    def test_stable_process_and_health_succeed(self):
        self.assertTrue(self.run_ready('ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=0\n', {'status': 'ok'}))

    def test_short_lived_active_process_is_not_success(self):
        self.assertFalse(self.run_ready('ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=0\n', {'status': 'ok'}, stable=2))


if __name__ == '__main__':
    unittest.main(verbosity=2)
