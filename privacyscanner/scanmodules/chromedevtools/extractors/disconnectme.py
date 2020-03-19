import io
import json

from collections import defaultdict
from urllib.parse import urlsplit

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file, file_is_outdated

_DISCONNECT_TP_SERVICES_URL = "https://github.com/disconnectme/disconnect-tracking-protection/raw/master/services.json"

_disconnect_tp_services = None


class DisconnectmeExtractor(Extractor):
    """
        Maps third-party domains to categories and companies using the disconnect.me list.
    """

    RESULT_KEY = 'third_parties_disconnectme'

    def extract_information(self):
        if 'third_parties' not in self.result or 'fqdns' not in self.result['third_parties']:
            self.logger.error("Missing `third_parties` or `fqdns`.")
            return

        third_party_companies = {
            'category_company_fqdns': defaultdict(lambda: defaultdict(list)),
            'unrecognized_fqdns': []
        }

        third_party_domains = self.result['third_parties']['fqdns']
        if third_party_domains and len(third_party_domains) > 0:
            self._load_disconnect_tp_services()

            for domain in third_party_domains:
                parsed_domain = parse_domain(domain)
                category_company = self._find_by_closest_subdomain(parsed_domain.fqdn, parsed_domain.registered_domain)
                category, company = category_company if category_company else (None, None)
                fqdn = parsed_domain.fqdn
                if category and company:
                    if fqdn not in third_party_companies['category_company_fqdns'][category][company]:
                        third_party_companies['category_company_fqdns'][category][company].append(fqdn)
                else:
                    if category or company:
                        self.logger.error("Found company without category or vice-versa")
                    if fqdn not in third_party_companies['unrecognized_fqdns']:
                        third_party_companies['unrecognized_fqdns'].append(fqdn)

        # defaultdict doesn't serialize to json properly -> convert to normal dict
        third_party_companies['category_company_fqdns'] = {k: dict(v) for k, v in
                                                           third_party_companies['category_company_fqdns'].items()}
        third_party_companies['unrecognized_fqdns'].sort()

        self.result[self.RESULT_KEY] = third_party_companies
        self.result.mark_dirty(self.RESULT_KEY)

    # TODO: optimally this should exclude (private) PSL TLDs
    def _find_by_closest_subdomain(self, start_domain, stop_domain):
        current_domain = start_domain
        for category in self.services['categories']:
            for entity in self.services['categories'][category]:
                for company, details in entity.items():
                    for homepage_netloc, operated_domains in details.items():
                        if current_domain in operated_domains or current_domain == homepage_netloc:
                            return category, company

        if current_domain == stop_domain:
            return None

        # TODO: rewrite like its done in trackerradar.py
        split = start_domain.split('.', maxsplit=1)
        if len(split) < 2:
            return None
        current_domain = split[1]

        return self._find_by_closest_subdomain(current_domain, stop_domain)

    def _load_disconnect_tp_services(self):
        global _disconnect_tp_services

        if _disconnect_tp_services is not None:
            self.services = _disconnect_tp_services
            return

        with open(self.options['storage_path'] / 'disconnect-tp-services.json') as f:
            self.services = json.load(f)
            _disconnect_tp_services = self.services

    @staticmethod
    def update_dependencies(options):
        lookup_file = options['storage_path'] / 'disconnect-tp-services.json'
        if not file_is_outdated(lookup_file, 3600 * 24 * 7):
            return
        buf = io.BytesIO()
        download_url = options.get('disconnect_services_url', _DISCONNECT_TP_SERVICES_URL)
        download_file(download_url, buf)
        services_data = json.loads(buf.getvalue())
        # strip the homepage down to the netloc
        # (it is not always included in the operated_domains)
        # doing this eagerly avoids continuously clobbering the urllib parse cache
        for category in services_data['categories']:
            for entity in services_data['categories'][category]:
                for name in entity:
                    entity[name] = {
                        urlsplit(homepage)[1]: operated_domains
                        for homepage, operated_domains in entity[name].items()
                        # some entries, e.g. Cryptomining contain "performance": "true", so filter those
                        if homepage.startswith('http')
                    }

        with lookup_file.open('w') as f:
            json.dump(services_data, f)
