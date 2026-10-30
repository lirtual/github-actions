"""Spec #51: direct Owner-base targets, no per-Task directory allocation."""
import json
import sys
from pathlib import Path
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / '.github/scripts'
sys.path.insert(0, str(SCRIPTS))
from download_batch import validate, InvalidBatch
import download_destination as dest


def batch(*links):
    return validate(json.dumps({
        'remote': 'koofr',
        'downloads': links,
        'project_purpose': 'repository release test',
    }))


class DestinationTests(unittest.TestCase):
    def test_direct_downloads_filename_default(self):
        b = batch({'url': 'https://example.org/release.rpm'})
        items = dest.plan_targets(b, [['release.rpm']], 'Downloads')
        self.assertEqual(['Downloads/release.rpm'],
                         [x['remote_target'] for x in items])
        self.assertEqual('release.rpm', items[0]['relative_target'])
        self.assertNotIn('run-', items[0]['remote_target'])

    def test_optional_relative_directory_still_available(self):
        b = batch({'url': 'https://example.org/a.zip', 'destination_dir': 'build/first'},
                  {'url': 'https://example.org/b.zip', 'destination_dir': 'build/second'})
        items = dest.plan_targets(b, [['same.zip'], ['same.zip']], 'Downloads')
        self.assertEqual(['Downloads/build/first/same.zip',
                          'Downloads/build/second/same.zip'],
                         [x['remote_target'] for x in items])

    def test_same_filename_in_flat_batch_fails_before_write(self):
        b = batch({'url': 'https://example.org/a'},
                  {'url': 'https://example.org/b'})
        for files in ([['same.rpm'], ['same.rpm']],
                      [['File.rpm'], ['file.rpm']],
                      [['a/nested'], ['a']]):
            with self.subTest(files=files), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(b, files, 'Downloads')

    def test_nested_file_keeps_safe_relative_path(self):
        b = batch({'url': 'https://example.org/a'})
        result = dest.plan_targets(b, [['nested/release.rpm']], 'Downloads')
        self.assertEqual('Downloads/nested/release.rpm', result[0]['remote_target'])

    def test_reject_unsafe_files_and_bad_batches(self):
        b = batch({'url': 'https://example.org/a'}, {'url': 'https://example.org/b'})
        for files in ([], [['a.zip']], [['a.zip'], []],
                      [['a.zip'], ['/other']], [['a.zip'], ['../other']],
                      [['a.zip'], ['abc//file']], [['a.zip'], ['abc:unsafe']],
                      [['a.zip'], ['foo\\bar']], [['a.zip'], ['']],
                      [['a.zip'], ['COM1']]):
            with self.subTest(files=files), self.assertRaises(dest.DestinationUnverified):
                dest.plan_targets(b, files, 'Downloads')

    def test_base_must_be_explicit_and_safe(self):
        for value in (None, '', '.', '/', '/Koofr', '..', 'a/../b',
                      'a//b', 'a\\b', 'a:b', 'dir/', 'C:/dir',
                      'dir/CON', 'dir/..', 'dir/%2e', 'dir/aux', 'dir/space '):
            with self.subTest(value=value), self.assertRaises(dest.DestinationUnverified):
                dest.approved_base_dir(value)
        self.assertEqual('Downloads', dest.approved_base_dir('Downloads'))
        self.assertEqual('Projects/Artifacts',
                         dest.approved_base_dir('Projects/Artifacts'))

    def test_untrusted_target_control_is_never_accepted(self):
        b = json.loads(json.dumps({'remote':'koofr', 'project_purpose':'test',
                                  'downloads':[{'url':'https://example.org/a'}]}))
        for key in ('task_root', 'remote_base_dir', 'target_path', 'overwrite'):
            value = dict(b)
            value[key] = 'Downloads/other'
            with self.subTest(key=key), self.assertRaises(InvalidBatch):
                validate(json.dumps(value))


if __name__ == '__main__':
    unittest.main()
