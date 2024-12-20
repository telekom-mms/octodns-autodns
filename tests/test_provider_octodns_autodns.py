#
#
#

from os.path import dirname, join
from unittest import TestCase

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.zone import Zone

from octodns_autodns import AutoDNSClientNotFound, AutoDNSProvider


class TestAutoDNSProvider(TestCase):
    expected = Zone("unit.tests.", [])
    source = YamlProvider("test", join(dirname(__file__), "config"))
    source.populate(expected)

    def test_populate(self):
        provider = AutoDNSProvider("test", "username", "password", 4)

        # Bad auth
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=401,
                text='{"message":"Invalid authentication credentials"}',
            )

            with self.assertRaises(Exception) as ctx:
                zone = Zone("unit.tests.", [])
                provider.populate(zone)
            self.assertEqual("Unauthorized", str(ctx.exception))

        # General error
        with requests_mock() as mock:
            mock.get(ANY, status_code=502, text="Things caught fire")

            with self.assertRaises(HTTPError) as ctx:
                zone = Zone("unit.tests.", [])
                provider.populate(zone)
            self.assertEqual(502, ctx.exception.response.status_code)

        # Non-existent zone doesn't populate anything
        with requests_mock() as mock:
            mock.get(
                ANY,
                status_code=404,
                text="""{
                    "stid": "20241220-app4-244741",
                    "messages": [
                        {
                            "text": "Diese Zone ist bisher nicht eingetragen.",
                            "objects": [
                                {
                                    "type": "zone",
                                    "value": "unit.tests"
                                }
                            ],
                            "code": "EF02020",
                            "status": "ERROR"
                        }
                    ],
                    "status": {
                        "code": "E0205",
                        "text": "Zonen-Informationen konnten nicht ermittelt werden.",
                        "type": "ERROR"
                    },
                    "object": {
                        "type": "Zone",
                        "value": "unit.tests"
                    }
                }""",
            )

            with self.assertRaises(AutoDNSClientNotFound) as ctx:
                zone = Zone("unit.tests.", [])
                provider.populate(zone)

        # No diffs == no changes
        with requests_mock() as mock:
            base = provider.client.BASE_URL
            with open('tests/fixtures/unit.tests.zone.json') as fh:
                mock.get(f'{base}/zone/unit.tests./a.ns14.net', text=fh.read())

            zone = Zone('unit.tests.', [])
            provider.populate(zone)
            self.assertEqual(10, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(0, len(changes))
