from unittest import TestCase

from envscope.region_profiles import countries, profiles, profile, validate_profile


class RegionCatalogTests(TestCase):
    def test_common_node_countries_have_real_timezone_mappings_on_both_platforms(self):
        expected = {'NL', 'IE', 'CH', 'IT', 'ES', 'SE', 'FI', 'NO', 'PL', 'IN', 'BR',
                    'ZA', 'TH', 'MY', 'NZ', 'ID', 'AE', 'PH', 'VN', 'CN', 'RU'}
        self.assertTrue(expected <= {c['code'] for c in countries()})
        for system in ('Windows', 'Darwin'):
            rows = profiles(system)
            self.assertGreaterEqual(len(rows), 400)
            self.assertEqual(len(rows), len({r['id'] for r in rows}))
            self.assertTrue(expected <= {r['country'] for r in rows})
            for row in rows:
                validate_profile(dict(region_profile=row['id'], **{k: row[k] for k in ('country', 'timezone', 'locale')}))
                self.assertNotIn('usage_country', row)

    def test_saved_ids_are_stable_and_timezone_aliases_are_available(self):
        self.assertEqual(profile('us-new-york', 'Windows')['timezone'], 'Eastern Standard Time')
        self.assertEqual(profile('sg-singapore', 'Darwin')['locale'], 'en_SG')
        india = [r for r in profiles('Windows') if r['country'] == 'IN']
        self.assertTrue(any('Asia/Kolkata' in r['aliases'] and r['timezone'] == 'India Standard Time' for r in india))
        self.assertTrue(any(r['iana'] == 'Europe/Amsterdam' and r['locale'] == 'nl-NL' for r in profiles('Windows')))

    def test_adding_region_choices_does_not_make_unsupported_actual_location_pass(self):
        from envscope.regions import region_finding
        for code in ('CN', 'RU'):
            self.assertTrue(any(p['country'] == code for p in profiles('Windows')))
            # The separately maintained service policy remains authoritative.
            self.assertEqual(region_finding([], {'usage_country': code, 'country': 'US'}).status.value, 'fail')
