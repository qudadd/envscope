import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from envscope.model import Finding
from envscope.regions import region_finding, API_REGIONS, CLAUDE_REGIONS, CHECKED_AT
from envscope.remedies import ConfigRemedies, SolutionPlans
from envscope.state import validate_settings
from scripts.environment_fixtures import report, target


def check(declared='US', exit_country='US', **changes):
    evidence = [{'actual':exit_country, 'expected':changes.get('country')}] if exit_country else []
    rows = [Finding('baseline.country','出口国家','pass','fixture','fixture',evidence)]
    return region_finding(rows, {'usage':'desktop','usage_country':declared, **changes})


class RegionTests(unittest.TestCase):
    def test_official_snapshots_keep_restricted_regions_out(self):
        self.assertEqual((len(API_REGIONS),len(CLAUDE_REGIONS)), (175,176))
        self.assertEqual(CLAUDE_REGIONS-API_REGIONS, {'MP'})
        self.assertEqual(CHECKED_AT, '2026-10-28')
        for country in ('CN','RU','HK','MO','BY','IR','KP'):
            self.assertNotIn(country, CLAUDE_REGIONS)
            self.assertNotIn(country, API_REGIONS)
        self.assertIn('TW', API_REGIONS)
        self.assertNotIn('ET', API_REGIONS, 'Do not activate the future-dated November policy early')

    def test_declared_exit_or_target_cn_ru_always_fail(self):
        for country in ('CN','RU'):
            for usage in ('web','desktop','cli','both'):
                for field in ('declared','exit_country','country'):
                    with self.subTest(country=country,usage=usage,field=field):
                        result = check(usage=usage, **{field:country})
                        self.assertEqual(result.status,'fail')
                        self.assertIn('官方不支持', result.summary)
                        self.assertFalse(result.evidence[0]['physical_location_verified'])

    def test_timezone_and_language_are_not_location(self):
        self.assertEqual(check(timezone='China Standard Time',locale='zh-CN',language='zh-CN').status, 'pass')
        self.assertEqual(check('TW','TW',usage='cli').status, 'pass')
        self.assertEqual(check('cn','US').status, 'fail')

    def test_unknown_exit_or_location_cannot_qualify(self):
        for actual, observed in (('', 'US'), ('US',None), (None,'RU'), ('US',''), ('US','not-a-country')):
            with self.subTest(actual=actual,observed=observed):
                self.assertNotEqual(check(actual,observed).status, 'pass')
        self.assertEqual(check('UA','UA').status,'warn')
        self.assertEqual(check(provider='vertex',usage='cli').status,'unknown')

    def test_mixed_exit_evidence_cannot_hide_unsupported_country(self):
        rows = [Finding('baseline.country','出口','pass','fixture','fixture',[{'actual':'US'}]),
                Finding('http.egress','出口','pass','fixture','fixture',[{'country':'CN'},{'country':'US'}])]
        result = region_finding(rows, {'usage':'cli','usage_country':'US','country':'US'})
        self.assertEqual(result.status,'fail')
        self.assertEqual(result.evidence[0]['observed_countries'], ['CN','US'])

    def test_region_failure_blocks_qualification_launch_and_repair(self):
        for system in ('Windows','Darwin'):
            for country in ('CN','RU'):
                with self.subTest(system=system,country=country), tempfile.TemporaryDirectory() as directory:
                    settings = target(system,usage='both',usage_country=country)
                    value = report(directory,settings,system)
                    self.assertEqual(value['assessment']['verdict'],'needs_fix')
                    self.assertFalse(value['launch']['ready'])
                    self.assertEqual(next(row for row in value['claude_checks']['items'] if row['id']=='country')['status'],'fail')
                    config = ConfigRemedies(directory,Path(directory)/'desktop',environ={})
                    config.preview = Mock(side_effect=AssertionError('Region restriction is not a config repair'))
                    solutions = SolutionPlans(config,Mock(),Mock(),Mock())
                    planned = solutions.prepare(value,enhance_cli=True)
                    self.assertEqual(planned['state'],'guided')
                    self.assertFalse(planned['effects'])
                    solutions.proxy_tester.assert_not_called()

    def test_cli_exit_cannot_claim_success_when_region_is_failed_or_missing(self):
        from envscope.cli import exit_status, parser
        self.assertEqual(parser().parse_args(['audit','--usage-country','CN']).usage_country,'CN')
        report={'decision':{'verdict':'clear_in_scope'},'findings':[]}
        self.assertEqual(exit_status(report),2)
        report['findings']=[{'id':'target.region','status':'fail'}]
        self.assertEqual(exit_status(report),1)
        report['findings'][0]['status']='pass'
        self.assertEqual(exit_status(report),0)

    def test_country_declaration_is_normalized_not_inferred(self):
        self.assertEqual(validate_settings({'usage_country':'cn'})['usage_country'],'CN')
        self.assertEqual(validate_settings({'timezone':'China Standard Time','locale':'zh-CN'})['usage_country'],'')
        for value in (True, 42, 'China','C','<script>'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_settings({'usage_country':value})
