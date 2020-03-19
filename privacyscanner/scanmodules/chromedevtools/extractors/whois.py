from collections import defaultdict

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


class ThirdPartyWhoisExtractor(Extractor):
    """
        Maps yet unidentified third parties to whois registrant organization
        TODO: on hold - reconsider after thesis results
    """

    RESULT_KEY = 'third_parties_whois'

    def extract_information(self):
        third_party_whois = {
            # dict indexed by registrant_organization
            'registrant_fqdns': defaultdict(lambda: {
                'registrant_name': None,
                'registrant_organization': None,
                'admin_name': None,
                'admin_organization': None,
                'tech_name': None,
                'tech_organization': None,
                'fqdns': [],
            }),
            'unrecognized_fqdns': []
        }

        third_party_domains = self.result['third_parties']['fqdns']
        if len(third_party_domains) > 0:
            for domain in third_party_domains:
                # skip cases there were already identified by previous steps to reduce requests
                if self._already_identified(domain):
                    continue

                parsed_domain = parse_domain(domain)

                #  TODO: implement whois integration (likely requires a payed service due toe usage limits)
                data = {
                    'registrant_name': None,
                    'registrant_organization': None,
                    'admin_name': None,
                    'admin_organization': None,
                    'tech_name': None,
                    'tech_organization': None,
                    'fqdns': [],
                }

                locals().update(data)

                fqdn = parsed_domain.fqdn
                if data:
                    org = data['registrant_organization']
                    # TODO: multiple domains may have the same registrant_organization, but different
                    #       other data. Must merge somehow or just dump everything into a list of aliases
                    #       for later analysis, as long as we just use this for privacy policy stuff...
                    org_dict = third_party_whois['registrant_fqdns'][org]
                    org_dict['registrant_name'] = org
                    # ... other entries
                    if fqdn not in org_dict['fqdns']:
                        third_party_whois['registrant_fqdns'][org]['fqdns'].append(fqdn)
                else:
                    if fqdn not in third_party_whois['unrecognized_fqdns']:
                        third_party_whois['unrecognized_fqdns'].append(fqdn)

        third_party_whois['registrant_fqdns'] = dict(third_party_whois['registrant_fqdns'])
        third_party_whois['unrecognized_fqdns'].sort()

        self.result[self.RESULT_KEY] = third_party_whois
        self.result.mark_dirty(self.RESULT_KEY)

    def _already_identified(self, domain):
        # TODO: None-safety
        return any(domain in fqdns for company_fqdns in
                   self.result['third_parties_disconnectme']['category_company_fqdns'].values() for fqdns in
                   company_fqdns.values()) or \
               any(domain == fqdn for fqdn in self.result['organizations']['domains']) or \
               any(domain in fqdns for fqdns in self.result['third_parties_tracker_radar']['owners'])

    def _identified_by_whotracksme(self, domain):
        return any(domain == fqdn for fqdn in self.result['organizations']['domains'])
