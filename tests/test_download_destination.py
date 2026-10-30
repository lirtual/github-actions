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
        root = dest.new_task_root('40904641278', '2')
        self.assertRegex(root, r'^downloads/run-40904641278-2-[a-f0-9]{32}$')
        self.assertNotEqual(root, dest.new_task_root('40904641278', '2'))
        self.assertFalse(root.startswith('/'))
        self.assertEqual(root, dest.verify_task_root(root))

    def test_reject_untrusted_identifiers_and_forged_task_roots(self):
        for bad in ['', '0', '-1', '1/2', 'abc', '1'*21, ' 1', '1\n', True, 1, None]:
            with self.subTest(bad=bad), self.assertRaises(dest.DestinationUnverified):
                dest.new_task_root(bad, '1')
        for wrong in ('downloads/run-123-1-deadbeef',
                      'downloads/run-123-1-' + 'f'*32 + '/sub',
                      '/downloads/run-123-1-' + 'f'*32,
                      'uploads/run-123-1-' + 'f'*32,
                      'downloads/run-0-1-' + 'f'*32,
                      'downloads/run-123-0-' + 'f'*32):
            with self.subTest(wrong=wrong), self.assertRaises(dest.DestinationUnverified):
                dest.verify_task_root(wrong)

    def test_files_stay_within_root_and_use_source_relative_directories(self):
        batch = validate(BATCH)
        root = dest.new_task_root('40904641278','1')
        plan = dest.plan_targets(batch, [['a.zip'], ['nested/b.zip']], root)
        self.assertEqual(['release/assets/a.zip', 'release/assets/nested/b.zip'],
                         [row['relative_target'] for row in plan])
        self.assertTrue(all(row['remote_target'].startswith(root+'/') for row in plan))
        self.assertEqual([0, 1], [row['source_index'] for row in plan])
        self.assertFalse(any(row['remote_target'].startswith('release/') for row in plan))

    def test_alias_and_overlap_rejected_across_sources_before_any_upload(self):
        batch = validate(BATCH)
        root = dest.new_task_root('11','1')
        for files in ([['a.zip'], ['a.zip']], [['File.zip'], ['file.zip']],
                      [['file.zip'], ['file.zip/nested']],
                      [['a/nested'], ['a']]):
            with self.subTest(files=files), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(batch, files, root)

    def test_empty_unexpected_and_absolute_paths_are_rejected(self):
        batch = validate(BATCH);root=dest.new_task_root('11','1')
        for bad in ([], [['a.zip']], [['a.zip'], []],
                    [['a.zip'], ['/other']], [['a.zip'], ['../other']],
                    [['a.zip'], ['abc//file']], [['a.zip'], ['abc:unsafe']],
                    [['a.zip'], ['foo\\bar']], [['a.zip'], ['']],
                    [['a.zip'], ['COM1']]):
            with self.subTest(bad=bad), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(batch, bad, root)

    def test_cli_writes_one_root_to_github_output_without_logging_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'output'
            env = {**os.environ, 'GITHUB_RUN_ID': '12345',
                   'GITHUB_RUN_ATTEMPT': '4', 'GITHUB_OUTPUT': str(target)}
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
                              {'GITHUB_RUN_ATTEMPT': '0'}):
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
