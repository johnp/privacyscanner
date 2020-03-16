from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.extractors.utils import get_cname


class ThirdPartyExtractor(Extractor):
    def extract_information(self):
        third_parties = {
            'fqdns': set(),
            'cnames': dict(),
            'num_http_requests': 0,
            'num_https_requests': 0
        }
        first_party_domains = set()
        for url in (self.result['site_url'], self.result['final_url']):
            extracted = parse_domain(url)
            first_party_domains.add(extracted.registered_domain)
        for request in self.page.request_log:
            request['is_thirdparty'] = False
            if request['url'].startswith('data:'):
                continue

            extracted_url = parse_domain(request['url'])
            parsed_url = request['parsed_url']
            if extracted_url.registered_domain in first_party_domains:
                # Test if first-party fqdn resolves to a CNAME => may be CNAME tracking
                # Note: We rely on the resolver to handle multi-level CNAME indirection. Also, a CNAME record should
                # have the same effect on A and AAAA requests, so we can get away with just checking one of them.
                cname = get_cname(self, extracted_url.fqdn, 'A')
                if cname is None:
                    continue  # no CNAME or lookup failed
                parsed_cname = parse_domain(cname)
                if parsed_cname.registered_domain in first_party_domains or cname == self.result.get('final_url_cname',
                                                                                                     None):
                    continue  # points to first-party sub-domain or to the same CNAME as final_url
                # else remember the third-party cname and continue like for a normal third-party request
                third_parties['cnames'][extracted_url.fqdn] = parsed_cname.fqdn
                result_cname = parsed_cname
            else:
                result_cname = None

            request['is_thirdparty'] = True
            third_parties['fqdns'].add(extracted_url.fqdn)
            if result_cname:
                third_parties['fqdns'].add(result_cname.fqdn)
            if parsed_url.scheme not in ('http', 'https'):
                continue
            third_parties['num_{}_requests'.format(parsed_url.scheme)] += 1
        third_parties['fqdns'] = list(third_parties['fqdns'])
        third_parties['fqdns'].sort()
        self.result['third_parties'] = third_parties

        for cookie in self.result['cookies']:
            domain = cookie['domain']
            if domain.startswith('.'):
                domain = domain[1:]
            domain = parse_domain(domain).registered_domain
            cookie['is_thirdparty'] = domain not in first_party_domains
        self.result.mark_dirty('cookies')
