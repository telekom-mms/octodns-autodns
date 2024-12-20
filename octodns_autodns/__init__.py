"""
octodns provider for AutoDNS
"""

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
    """
    AutoDNSClientException for AutoDNSClientNotFound and AutoDNSClientUnauthorized
    """


class AutoDNSClientNotFound(AutoDNSClientException):
    """
    AutoDNSClientNotFound if client not found
    """

    def __init__(self):
        super().__init__('Not Found')


class AutoDNSClientUnauthorized(AutoDNSClientException):
    """
    AutoDNSClientUnauthorized if client is unauthorized
    """

    def __init__(self):
        super().__init__('Unauthorized')


class AutoDNSClient(object):
    """
    AutoDNSClient main class
    """

    BASE_URL = 'https://api.autodns.com/v1'

    def __init__(self, session: Session, system_name_server: str):
        self._session = session
        self.system_name_server = system_name_server

    def _do(self, method, path, params=None, data=None):
        """
        Requests data from the AutoDNS API using the configured credentials
        """
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
        """
        Downloads Zone configuration from AutoDNS API
        """
        return self._do_json('GET', f'/zone/{name}/{self.system_name_server}')

    # TODO: implement creating new zones in AutoDNS, haven't done this so far
    def zone_create(self, origin, soa, nameservers):
        """
        Creates a new zone in AutoDNS API
        """
        data = {'origin': origin, 'soa': soa, 'nameservers': nameservers}
        return self._do_json('POST', '/zone', data=data)['zone']

    def zone_update_records(
        self,
        zone_name: str,
        records_add: list[dict],
        records_remove: list[dict],
    ):
        """
        Updates changed Records in an existing AutoDNS zone
        """
        data = {'adds': records_add, 'rems': records_remove}
        return self._do_json('POST', f'/zone/{zone_name}/_stream', data=data)


class AutoDNSProvider(BaseProvider):
    """
    AutoDNSProvider main class
    """

    SUPPORTS_GEO = False
    # SUPPORTS_DYNAMIC = False
    # SUPPORTS_ROOT_NS = True
    SUPPORTS = set(
        ('A', 'AAAA', 'CAA', 'TXT', 'CNAME', 'MX', 'NS', 'SRV', 'ALIAS')
    )

    def __init__(
        self,
        id,
        username,
        password,
        context,
        *args,
        system_name_servers=(
            "a.ns14.net",
            "b.ns14.net",
            "c.ns14.net",
            "d.ns14.net",
        ),
        **kwargs,
    ):
        self.log = getLogger(f'AutoDNSProvider[{id}]')
        self.log.debug(
            "__init__: username=%s, password=%s, context=%s, system_name_servers=%s",
            username,
            password,
            context,
            system_name_servers,
        )

        super().__init__(id, *args, **kwargs)

        self.id = id

        sess = Session()
        sess.headers.update({"X-Domainrobot-Context": str(context)})
        sess.auth = HTTPBasicAuth(username, password)

        self.client = AutoDNSClient(sess, system_name_servers[0])

    def _data_for_mx(self, _type, records, default_ttl):
        values = []
        for record in records:
            preference = record.get('pref')
            value = record.get('value')
            values.append({'preference': int(preference), 'value': str(value)})
        try:
            _ttl = records[0]["ttl"]
        except KeyError:
            _ttl = default_ttl
        return {'ttl': _ttl, 'type': _type, 'values': values}

    def _data_for_multi(self, _type, records, default_ttl):
        values = []
        for record in records:
            values.append(record.get('value'))
        try:
            _ttl = records[0]["ttl"]
        except KeyError:
            _ttl = default_ttl
        return {'ttl': _ttl, 'type': _type, 'values': values}

    def _data_for_single(self, _type, records, default_ttl):
        record = records[0]
        try:
            _ttl = records[0]["ttl"]
        except KeyError:
            _ttl = default_ttl
        return {'ttl': _ttl, 'type': _type, 'value': record.get('value')}

    def _data_for_srv(self, _type, records, default_ttl):
        values = []
        for record in records:
            priority = record.get('pref')
            weight = record.get('value').split(' ')[0]
            port = record.get('value').split(' ')[1]
            target = record.get('value').split(' ')[2]
            values.append(
                {
                    'priority': priority,
                    'weight': weight,
                    'port': port,
                    'target': target,
                }
            )
        try:
            _ttl = records[0]["ttl"]
        except KeyError:
            _ttl = default_ttl

        return {'ttl': _ttl, 'type': _type, 'values': values}

    def _data_for_caa(self, _type, records, default_ttl):
        values = []
        for record in records:
            flags = record.get('value').split(' ')[0]
            tag = record.get('value').split(' ')[1]
            value = record.get('value').split(' ')[2]
            values.append({'flags': flags, 'tag': tag, 'value': value})
        try:
            _ttl = records[0]["ttl"]
        except KeyError:
            _ttl = default_ttl

        return {'ttl': _ttl, 'type': _type, 'values': values}

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'value': value,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_caa(self, record):
        for value in record.values:
            data = f'{value.flags} {value.tag} "{value.value}"'
            yield {
                'value': data,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
            }

    def _params_for_single(self, record):
        yield {
            'value': record.value,
            'name': record.name,
            'ttl': record.ttl,
            'type': record._type,
        }

    _params_for_CNAME = _params_for_single

    def _params_for_mx(self, record):
        for value in record.values:
            yield {
                'value': value.exchange,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
                'pref': value.preference,
            }

    _params_for_NS = _params_for_multiple

    def _params_for_srv(self, record):
        for value in record.values:
            data = f'{value.weight} {value.port} {value.target}'
            yield {
                'value': data,
                'name': record.name,
                'ttl': record.ttl,
                'type': record._type,
                'pref': value.priority,
            }

    _params_for_TXT = _params_for_multiple

    def _apply_create(self, zone_name, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')

        for params in params_for(new):
            self.client.zone_update_records(
                zone_name, records_remove=[], records_add=[params]
            )

    def _apply_update(self, zone_name, change):
        # It's way simpler to delete-then-recreate than to update
        self._apply_delete(zone_name, change)
        self._apply_create(zone_name, change)

    def _apply_delete(self, zone_name, change):
        existing = change.existing

        params_for = getattr(self, f'_params_for_{existing._type}')

        for params in params_for(existing):
            self.client.zone_update_records(
                zone_name, records_add=[], records_remove=[params]
            )

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(desired.name, change)

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
                        record_data = self._data_for_mx(
                            _type, records, default_ttl
                        )
                    case 'SRV':
                        record_data = self._data_for_srv(
                            _type, records, default_ttl
                        )
                    case 'CNAME' | 'ALIAS':
                        record_data = self._data_for_single(
                            _type, records, default_ttl
                        )
                    case 'CAA':
                        record_data = self._data_for_caa(
                            _type, records, default_ttl
                        )
                    case _:
                        record_data = self._data_for_multi(
                            _type, records, default_ttl
                        )

                record = Record.new(
                    zone, name, record_data, source=self, lenient=lenient
                )
                zone.add_record(record, lenient=lenient)

        self.log.info('populate:   found %s records', len(zone.records))
