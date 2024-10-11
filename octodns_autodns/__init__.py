#
# octodns provider for AutoDNS
#

from octodns.provider.base import BaseProvider
from octodns.provider import ProviderException
from octodns.record import Record
from octodns.zone import Zone

from collections import defaultdict
from logging import getLogger
from requests import Session
from requests.auth import HTTPBasicAuth

# TODO: remove __VERSION__ with the next major version release
__version__ = __VERSION__ = '0.0.1'

class AutoDNSClientException(ProviderException):
    pass

class AutoDNSClientNotFound(AutoDNSClientException):
    def __init__(self):
        super().__init__('Not Found')

class AutoDNSClientUnauthorized(AutoDNSClientException):
    def __init__(self):
        super().__init__('Unauthorized')

class AutoDNSClient(object):
    BASE_URL = 'https://api.autodns.com/v1'

    def __init__(self, session: Session, system_name_server: str):
        self._session = session
        self.system_name_server = system_name_server

    def _do(self, method, path, params=None, data=None):
        url = f'{self.BASE_URL}{path}'
        response = self._session.request(method, url, params=params, json=data)
        if response.status_code == 401:
            raise AutoDNSClientUnauthorized()
        if response.status_code == 404:
            raise AutoDNSClientNotFound()
        response.raise_for_status()
        return response

    def _do_json(self, method, path, params=None, data=None):
        return self._do(method, path, params, data).json()

    def zone_get(self, name):
        return self._do_json('GET', f'/zone/{name}/{self.system_name_server}')

    def zone_create(self, origin, soa, nameservers):
        data = {'origin': origin, 'soa': soa, 'nameservers': nameservers}
        return self._do_json('POST', '/zone', data=data)['zone']

    def zone_records_get(self, zone_id):
        params = {'zone_id': zone_id}
        records = self._do_json('GET', '/records', params=params)['records']
        for record in records:
            if record['name'] == '@':
                record['name'] = ''
        return records

    def zone_record_create(self, zone_id, name, _type, value, ttl=None):
        data = {
            'name': name or '@',
            'ttl': ttl,
            'type': _type,
            'value': value,
            'zone_id': zone_id,
        }
        self._do('POST', '/records', data=data)

    def zone_record_delete(self, zone_id, record_id):
        self._do('DELETE', f'/records/{record_id}')


class AutoDNSProvider(BaseProvider):
    SUPPORTS_GEO = False
    #SUPPORTS_DYNAMIC = False
    #SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        (
            'A',
            'AAAA',
            'CAA',
            'HINFO',
            'NAPTR',
            'PTR',
            'TXT',
            'CNAME',
            'MX',
            'NS',
            'SRV',
            'ALIAS'
        )
    )

    def __init__(
            self,
            id,
            username,
            password,
            context,
            system_name_server="a.ns14.net",
            *args,
            **kwargs
    ):
        self.log = getLogger(f'AutoDNSProvider[{id}]')
        self.log.debug(f"__init__: username={username}, password={password}, context={context}, system_name_server={system_name_server}")

        super().__init__(id, *args, **kwargs)

        self.id = id

        sess = Session()
        sess.headers.update({
            "X-Domainrobot-Context": str(context),
        })
        sess.auth = HTTPBasicAuth(username, password)

        self.client = AutoDNSClient(sess, system_name_server)

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug('populate: zone=%s', zone.name)
        before = len(zone.records)

        values = defaultdict(lambda: defaultdict(list))
        zone_data = self.client.zone_get(zone.name)
        for record in zone_data["data"][0]["resourceRecords"]:

            _type = record['type']
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][record['type']].append(record)

        for name, types in values.items():
            for _type, records in types.items():
                print(_type, records)
                record_data = records[0]
                record = Record.new(
                    zone,
                    name,
                    {
                        'ttl': record_data.get("ttl", zone_data["data"][0]["soa"]["ttl"]),
                        'type': record_data["type"],
                        'value': record_data["value"],
                    },
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records', len(zone.records) - before
        )
