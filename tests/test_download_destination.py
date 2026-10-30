"""Spec #51 Q15/Q38 revised: every Task owns one isolated random root."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / '.github/scripts'
sys.path.insert(0, str(SCRIPTS))
from download_batch import validate, InvalidBatch
import download_destination as dest


BATCH = ('{"remote":"onedrive","downloads":['
         '{"url":"https://example.org/a.zip","destination_dir":"release/assets"},'
         '{"url":"https://example.org/b.zip","destination_dir":"release/assets"}],'
         '"project_purpose":"release test"}')


class DestinationTests(unittest.TestCase):
    def test_generated_root_must_contain_trusted_run_and_random_128_bits(self):
        root = dest.new_task_root('40904641278', '2', 'downloads')
        self.assertRegex(root, r'^downloads/run-40904641278-2-[a-f0-9]{32}$')
        self.assertNotEqual(root, dest.new_task_root('40904641278', '2', 'downloads'))
        self.assertFalse(root.startswith('/'))
        self.assertEqual(root, dest.verify_task_root(root, 'downloads'))

    def test_reject_untrusted_identifiers_and_forged_task_roots(self):
        for bad in ['', '0', '-1', '1/2', 'abc', '1'*21, ' 1', '1\n', True, 1, None]:
            with self.subTest(bad=bad), self.assertRaises(dest.DestinationUnverified):
                dest.new_task_root(bad, '1', 'downloads')
        for wrong in ('downloads/run-123-1-deadbeef',
                      'downloads/run-123-1-' + 'f'*32 + '/sub',
                      '/downloads/run-123-1-' + 'f'*32,
                      'uploads/run-123-1-' + 'f'*32,
                      'downloads/run-0-1-' + 'f'*32,
                      'downloads/run-123-0-' + 'f'*32):
            with self.subTest(wrong=wrong), self.assertRaises(dest.DestinationUnverified):
                dest.verify_task_root(wrong, 'downloads')

    def test_files_stay_within_root_and_use_source_relative_directories(self):
        batch = validate(BATCH)
        root = dest.new_task_root('40904641278','1', 'downloads')
        plan = dest.plan_targets(batch, [['a.zip'], ['nested/b.zip']], root, 'downloads')
        self.assertEqual(['release/assets/a.zip', 'release/assets/nested/b.zip'],
                         [row['relative_target'] for row in plan])
        self.assertTrue(all(row['remote_target'].startswith(root+'/') for row in plan))
        self.assertEqual([0, 1], [row['source_index'] for row in plan])
        self.assertFalse(any(row['remote_target'].startswith('release/') for row in plan))

    def test_alias_and_overlap_rejected_across_sources_before_any_upload(self):
        batch = validate(BATCH)
        root = dest.new_task_root('11','1', 'downloads')
        for files in ([['a.zip'], ['a.zip']], [['File.zip'], ['file.zip']],
                      [['file.zip'], ['file.zip/nested']],
                      [['a/nested'], ['a']]):
            with self.subTest(files=files), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(batch, files, root, 'downloads')

    def test_empty_unexpected_and_absolute_paths_are_rejected(self):
        batch = validate(BATCH);root=dest.new_task_root('11','1', 'downloads')
        for bad in ([], [['a.zip']], [['a.zip'], []],
                    [['a.zip'], ['/other']], [['a.zip'], ['../other']],
                    [['a.zip'], ['abc//file']], [['a.zip'], ['abc:unsafe']],
                    [['a.zip'], ['foo\\bar']], [['a.zip'], ['']],
                    [['a.zip'], ['COM1']]):
            with self.subTest(bad=bad), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(batch, bad, root, 'downloads')

    def test_custom_base_preserves_task_isolation_and_mapping(self):
        base = 'Projects/Artifacts'
        first = dest.new_task_root('11', '1', base)
        second = dest.new_task_root('11', '1', base)
        self.assertNotEqual(first, second)
        self.assertRegex(first, r'^Projects/Artifacts/run-11-1-[a-f0-9]{32}$')
        self.assertEqual(first, dest.verify_task_root(first, base))
        self.assertRaises(dest.DestinationUnverified,
                          dest.verify_task_root, first, 'downloads')
        plan = dest.plan_targets(validate(BATCH), [['a.zip'], ['b.zip']],
                                 first, base)
        self.assertTrue(all(x['remote_target'].startswith(first + '/')
                            for x in plan))

    def test_base_must_be_explicit_and_safe(self):
        for value in (None, '', '.', '/', '/Koofr', '..', 'a/../b',
                      'a//b', 'a\\b', 'a:b', 'dir/', 'C:/dir',
                      'dir/CON', 'dir/..', 'dir/%2e', 'dir/aux',
                      'dir/space ', 'dir\u212b'):
            with self.subTest(base=value), self.assertRaises(
                    dest.DestinationUnverified):
                dest.approved_base_dir(value)
        self.assertEqual('Projects/Artifacts',
                         dest.approved_base_dir('Projects/Artifacts'))
        for base in (None, '', '../wrong'):
            with self.assertRaises(dest.DestinationUnverified):
                dest.new_task_root('11', '1', base)

    def test_root_cannot_be_forged_outside_configured_base(self):
        suffix = 'run-123-1-' + 'f' * 32
        for root in ('Projects/Artifacts/' + suffix + '/escaped',
                     'Projects/Artifacts/../' + suffix,
                     'Projects/ArtifactsX/' + suffix,
                     'Projects/Artifacts/' + suffix.upper(),
                     'downloads/' + suffix):
            with self.subTest(root=root), self.assertRaises(
                    dest.DestinationUnverified):
                dest.verify_task_root(root, 'Projects/Artifacts')

    def test_cli_writes_one_root_to_github_output_without_logging_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'output'
            env = {**os.environ, 'GITHUB_RUN_ID': '12345',
                   'GITHUB_RUN_ATTEMPT': '4', 'GITHUB_OUTPUT': str(target),
                   'DOWNLOAD_REMOTE_BASE_DIR': 'downloads'}
            command = [sys.executable, str(SCRIPTS / 'download_destination.py')]
            ok = subprocess.run(command, env=env, capture_output=True, text=True)
            if os.name != 'posix':
                self.assertEqual(2, ok.returncode)
                self.assertIn('TASK_ROOT_UNAVAILABLE', ok.stderr)
                self.assertFalse(target.exists())
                return
            self.assertEqual(0, ok.returncode, ok.stderr)
            data = target.read_text()
            self.assertRegex(data, r'^task_root=downloads/run-12345-4-[a-f0-9]{32}\n$')
            self.assertIn('::add-mask::downloads/run-12345-4-', ok.stdout)
            self.assertNotIn('run-12345-4-', ok.stderr)
            for overrides in ({'GITHUB_RUN_ID': '../../escape'}, {'GITHUB_OUTPUT': ''},
                              {'GITHUB_RUN_ATTEMPT': '0'},
                              {'DOWNLOAD_REMOTE_BASE_DIR': ''},
                              {'DOWNLOAD_REMOTE_BASE_DIR': '../escape'}):
                bad = subprocess.run(command, env={**env, **overrides},
                                     capture_output=True, text=True)
                self.assertNotEqual(0, bad.returncode)
                self.assertNotIn('downloads/run-', bad.stdout + bad.stderr)

        import json
        batch=json.loads(BATCH);batch['task_root']='downloads/run-1-1-'+'f'*32
        with self.assertRaises(InvalidBatch):
            validate(json.dumps(batch))


if __name__ == '__main__':
    unittest.main()
