import json
from pathlib import Path
import tempfile
import unittest

from envscope import __release__, __version__
from envscope.app_identity import APP_ID, build_identity, validate_identity, verify_package_identity


class AppIdentityTests(unittest.TestCase):
    def test_open_source_identity_is_stable_and_never_claims_publisher_trust(self):
        for system, mode in [('Windows','unsigned'),('Darwin','ad-hoc')]:
            value=build_identity(system)
            self.assertEqual(value['app_id'],APP_ID)
            self.assertEqual(value['version'],__version__)
            self.assertEqual(value['signature_mode'],mode)
            self.assertIs(value['publisher_verified'],False)
            self.assertIs(value['notarized'],False)
            self.assertEqual(validate_identity(value,system,__release__),value)

    def test_identity_release_platform_and_signature_claims_cannot_drift(self):
        original=build_identity('Windows')
        for change in ({'app_id':'another.app'},{'release':'v99.0.0-alpha.1'},{'system':'Darwin'},
                       {'version':'0.0.0'},{'signature_mode':'publisher'},{'publisher_verified':True},{'notarized':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                validate_identity({**original,**change},'Windows',__release__)

    def test_missing_changed_and_oversized_package_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            app=Path(folder)/'EnvScope';app.mkdir();exe=app/'EnvScope.exe';exe.write_bytes(b'MZ-fixture')
            with self.assertRaises(ValueError):verify_package_identity(exe,'Windows',__release__)
            path=app/'build-identity.json';path.write_text(json.dumps(build_identity('Windows')))
            self.assertEqual(verify_package_identity(exe,'Windows',__release__)['app_id'],APP_ID)
            path.write_text(' '*16385)
            with self.assertRaises(ValueError):verify_package_identity(exe,'Windows',__release__)
