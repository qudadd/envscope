import unittest

from envscope.client_config import tun_model,update_tun


class ClientConfigTests(unittest.TestCase):
    def test_only_tun_flag_changes_and_comments_quotes_survive(self):
        raw=b'# user comment\nenable_tun_mode: false # keep\nlanguage: "zh-CN"\nother: {items: [1, true]}\n'
        after=update_tun(raw,{'present':True,'value':True})
        self.assertEqual(tun_model(after),{'present':True,'value':True})
        self.assertIn(b'# user comment',after);self.assertIn(b'# keep',after)
        self.assertIn(b'language: "zh-CN"',after);self.assertIn(b'items: [1, true]',after)

    def test_missing_and_explicit_unspecified_are_distinct_and_restorable(self):
        for raw in (b'other: 1\n',b'enable_tun_mode: null\nother: 1\n'):
            with self.subTest(raw=raw):
                original=tun_model(raw)
                changed=update_tun(raw,{'present':True,'value':True})
                restored=update_tun(changed,original)
                self.assertEqual(tun_model(restored),original)
        self.assertNotEqual(tun_model(b'other: 1'),tun_model(b'enable_tun_mode: null'))

    def test_unrelated_edits_are_preserved_on_field_restore(self):
        before=tun_model(b'enable_tun_mode: false\n')
        current=b'enable_tun_mode: true\n# added later\nlanguage: "ja"\n'
        restored=update_tun(current,before)
        self.assertIn(b'# added later',restored);self.assertIn(b'language: "ja"',restored)
        self.assertEqual(tun_model(restored),before)

    def test_unknown_types_merge_keys_and_malformed_yaml_are_rejected(self):
        for raw in (b'enable_tun_mode: "false"',b'enable_tun_mode: 1',b'enable_tun_mode: []',
                    b'enable_tun_mode: true\nenable_tun_mode: false',b'<<: {enable_tun_mode: false}',
                    b'enable_tun_mode: !run false'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):update_tun(raw,{'present':True,'value':True})
        for invalid in ({'present':1,'value':True},{'present':False,'value':True},
                        {'present':True,'value':'true'},{'present':True,'value':True,'extra':1}):
            with self.assertRaises(ValueError):update_tun(b'other: 1',invalid)

    def test_unchanged_values_retain_original_bytes_and_bom_is_preserved(self):
        raw=b'\xef\xbb\xbfenable_tun_mode: false\r\n'
        self.assertEqual(update_tun(raw,tun_model(raw)),raw)
        self.assertTrue(update_tun(raw,{'present':True,'value':True}).startswith(b'\xef\xbb\xbf'))
