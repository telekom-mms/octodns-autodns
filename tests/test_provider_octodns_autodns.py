#
#
#

from os.path import dirname, join
from unittest import TestCase
from unittest.mock import MagicMock, Mock, call

from requests import HTTPError
from requests_mock import ANY
from requests_mock import mock as requests_mock

from octodns.provider.yaml import YamlProvider
from octodns.record import Record
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
            self.assertEqual(15, len(zone.records))
            changes = self.expected.changes(zone, provider)
            self.assertEqual(0, len(changes))

    def test_apply(self):
        provider = AutoDNSProvider("test", "username", "password", 4)

        resp = Mock()
        resp.json = Mock()
        provider.client.zone_get = MagicMock(
            return_value={
                'data': [
                    {
                        "soa": {
                            "refresh": 43200,
                            "retry": 7200,
                            "expire": 1209600,
                            "ttl": 86400,
                            "email": "admin@example.com",
                        },
                        "resourceRecords": [],
                    }
                ]
            }
        )
        provider.client._do = Mock(return_value=resp)
        plan = provider.plan(self.expected)
        provider.apply(plan)

        self.assertFalse(plan.exists)

        provider.client._do.assert_has_calls(
            [
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "example",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "example2",
                                "ttl": 3600,
                                "type": "A",
                                "value": "1.2.3.4",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "mta",
                                "ttl": 600,
                                "type": "MX",
                                "value": "mta.unit.tests.",
                                "pref": 10,
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "mta2",
                                "ttl": 3600,
                                "type": "MX",
                                "value": "mta.unit.tests.",
                                "pref": 10,
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "test-ns",
                                "ttl": 600,
                                "type": "NS",
                                "value": "a.unit-tests.net.",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "test-ns",
                                "ttl": 600,
                                "type": "NS",
                                "value": "b.unit-tests.net.",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "unit.test",
                                "ttl": 600,
                                "type": "CNAME",
                                "value": "www.unit.tests.",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "unit2.test",
                                "ttl": 3600,
                                "type": "CNAME",
                                "value": "www.unit.tests.",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "",
                                "ttl": 600,
                                "type": "CAA",
                                "value": "0 issue \"letsencrypt.org\"",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "",
                                "ttl": 600,
                                "type": "CAA",
                                "value": "0 issuewild \"letsencrypt.org\"",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "",
                                "ttl": 600,
                                "type": "CAA",
                                "value": "0 iodef \"mailto:webmaster@unit.tests\"",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "",
                                "ttl": 600,
                                "type": "TXT",
                                "value": "octodns autodns test",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "value": "unit.tests.",
                                "name": "",
                                "ttl": 600,
                                "type": "ALIAS",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "www",
                                "ttl": 600,
                                "type": "AAAA",
                                "value": "30f0:2e76:9b3f:45d9:d25e:58c:5243:3c98",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "www",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "_srv._tcp",
                                "ttl": 600,
                                "type": "SRV",
                                "value": "10 8443 www.unit.tests.",
                                "pref": 20,
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "_srv2._tcp",
                                "ttl": 3600,
                                "type": "SRV",
                                "value": "10 8443 www.unit.tests.",
                                "pref": 20,
                            }
                        ],
                        'rems': [],
                    },
                ),
            ],
            any_order=True,
        )
        self.assertEqual(20, provider.client._do.call_count)

        provider.client._do.reset_mock()

        provider = AutoDNSProvider("test", "username", "password", 4)
        resp = Mock()
        resp.json = Mock()
        provider.client._do = Mock(return_value=resp)

        provider.client.zone_get = MagicMock(
            return_value={
                'data': [
                    {
                        "soa": {
                            "refresh": 43200,
                            "retry": 7200,
                            "expire": 1209600,
                            "ttl": 86400,
                            "email": "admin@example.com",
                        },
                        "resourceRecords": [
                            {
                                "name": "one",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            },
                            {
                                "name": "two",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            },
                        ],
                    }
                ]
            }
        )

        wanted = Zone('unit.tests.', [])
        wanted.add_record(
            Record.new(
                wanted, 'one', {'ttl': 600, 'type': 'A', 'value': '5.6.7.8'}
            )
        )

        plan = provider.plan(wanted)
        self.assertEqual(2, len(plan.changes))
        self.assertEqual(2, provider.apply(plan))

        self.assertFalse(plan.exists)

        provider.client._do.assert_has_calls(
            [
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [],
                        'rems': [
                            {
                                "name": "one",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            }
                        ],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [
                            {
                                "name": "one",
                                "ttl": 600,
                                "type": "A",
                                "value": "5.6.7.8",
                            }
                        ],
                        'rems': [],
                    },
                ),
                call(
                    'POST',
                    '/zone/unit.tests./_stream',
                    None,
                    {
                        'adds': [],
                        'rems': [
                            {
                                "name": "two",
                                "ttl": 600,
                                "type": "A",
                                "value": "1.2.3.4",
                            }
                        ],
                    },
                ),
            ],
            any_order=True,
        )
