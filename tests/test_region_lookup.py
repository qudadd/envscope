import json
from pathlib import Path
import tempfile
import unittest

from envscope.operations import Operations
from envscope.region_lookup import lookup_region
from envscope.state import StateStore
from envscope.transport import Response


class RegionLookupTests(unittest.TestCase):
    def call(self, trace='ip=8.8.8.8\nloc=US', info=None, status=200, tls=True, params=None):
        owner=self
        self.routes=[]
        class Transport:
            path='fixture'
            def get(self,url,family):
                owner.assertEqual(family,4)
                return Response(status=status,body=trace if 'cloudflare' in url else json.dumps(info if info is not None else {'ip':'8.8.8.8','country':'US','timezone':'America/New_York','city':'New York'}),tls_verified=tls)
        def factory(settings):
            self.routes.append(settings)
            return Transport()
        return lookup_region(params or {'connection_mode':'tun','target_proxy':''},factory)

    def test_agreement_suggests_without_saving_actual_country(self):
        result=self.call()
        self.assertEqual((result['state'],result['country'],result['timezone']),('observed','US','America/New_York'))
        with tempfile.TemporaryDirectory() as tmp:
            store=StateStore(Path(tmp)/'state')
            before=store.settings()
            ops=Operations(store,tmp,region_lookup=lambda params:result)
            self.assertEqual(ops.run('environment-location',{'connection_mode':'tun','target_proxy':''}),result)
            self.assertEqual(before,store.settings())

    def test_conflicting_countries_do_not_suggest(self):
        value=self.call(trace='ip=8.8.8.8\nloc=JP')
        self.assertEqual(value['state'],'conflict')
        self.assertEqual(value['country'],'')
        self.assertEqual(value['timezone'],'')

    def test_multiple_ips_and_single_source_do_not_choose_timezone(self):
        for trace in ('ip=1.1.1.1\nloc=US','ip=127.0.0.1\nloc=US','invalid'):
            value=self.call(trace=trace)
            self.assertEqual(value['state'],'partial')
            self.assertEqual(value['timezone'],'')

    def test_failures_and_invalid_payloads_are_not_observations(self):
        for changes in ({'status':429},{'tls':False},{'trace':'bad','info':[]},{'trace':'bad','info':{'ip':'127.0.0.1','country':'US'}}):
            self.assertEqual(self.call(**changes)['state'],'unavailable')

    def test_only_fixed_route_parameters_and_local_proxy(self):
        for p in ({'connection_mode':'tun','target_proxy':'http://127.0.0.1:7890'},
                  {'connection_mode':'http_proxy','target_proxy':'http://remote.example:7890'},
                  {'connection_mode':'direct','target_proxy':'','url':'https://other.example'}):
            with self.assertRaises(ValueError):self.call(params=p)
        self.call(params={'connection_mode':'http_proxy','target_proxy':'http://127.0.0.1:7890'})
        self.assertEqual(self.routes[0]['target_proxy'],'http://127.0.0.1:7890')


if __name__=='__main__':unittest.main()
