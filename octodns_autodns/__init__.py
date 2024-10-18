#
# octodns provider for AutoDNS
#

from collections import defaultdict
from logging import getLogger

from requests import Session
from requests.auth import HTTPBasicAuth

from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record
from octodns.zone import Zone

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
            system_name_servers=["a.ns14.net","b.ns14.net","c.ns14.net","d.ns14.net"],
            *args,
            **kwargs
    ):
        self.log = getLogger(f'AutoDNSProvider[{id}]')
        self.log.debug(f"__init__: username={username}, password={password}, context={context}, system_name_servers={system_name_servers}")

        super().__init__(id, *args, **kwargs)

        self.id = id

        sess = Session()
        sess.headers.update({
            "X-Domainrobot-Context": str(context),
        })
        sess.auth = HTTPBasicAuth(username, password)

        self.client = AutoDNSClient(sess, system_name_servers[0])

    def _data_for_MX(self, _type, records, default_ttl):
        values = []
        for record in records:
            preference = record.get('pref')
            value = record.get('value')
            values.append(
                {
                    'preference': int(preference),
                    'value': str(value),
                }
            )
        return {
            'ttl': record.get("ttl", default_ttl),
            'type': _type,
            'values': values,
        }

    def _data_for_A(self, _type, records, default_ttl):
        values = []
        for record in records:
            values.append(record.get('value'))
        return {
            'ttl': record.get("ttl", default_ttl),
            'type': _type,
            'values': values
        }

    def populate(self, zone: Zone, target=False, lenient=False):
        self.log.debug('populate: zone=%s', zone.name)
        values = defaultdict(lambda: defaultdict(list))
        zone_data = self.client.zone_get(zone.name)

        default_ttl = zone_data["data"][0]["soa"]["ttl"]

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

                match _type:
                    case 'MX':
                        record_data = self._data_for_MX(_type, records, default_ttl)
                    case 'A':
                        record_data = self._data_for_A(_type, records, default_ttl)

                # for record in records:
                #     record_data = record

                #     record_contents = {}

                #     record_contents["ttl"] = record_data.get("ttl", zone_data["data"][0]["soa"]["ttl"])
                #     record_contents["type"] = record_data.get('type')

                #     if record_data.get('type') == 'MX':
                #         record_contents['value'] = {}
                #         record_contents['value']['preference'] = record_data.get('pref')
                #         record_contents['value']['value'] = record_data.get('value')
                #     elif record_data.get('type') == 'SRV':
                #         record_contents['value'] = {}
                #         record_contents['value']['priority'] = record_data.get('pref')
                #         record_contents['value']['weight'] = record_data.get('value').split(' ')[0]
                #         record_contents['value']['port'] = record_data.get('value').split(' ')[1]
                #         record_contents['value']['target'] = record_data.get('value').split(' ')[2]
                #     else:
                #         record_contents["value"] = record_data.get('value')


                record = Record.new(
                    zone,
                    name,
                    record_data,
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records', len(zone.records) - before
        )
