from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.extractors.utils import get_cname


class FinalUrlExtractor(Extractor):
    def extract_information(self):
        self.result['final_url'] = self.page.final_response['url']
        self.result['final_url_cname'] = get_cname(self, parse_domain(self.result['final_url']).fqdn, 'A')
