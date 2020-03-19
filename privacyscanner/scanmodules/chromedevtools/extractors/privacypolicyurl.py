import json

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain
from privacyscanner.scanmodules.chromedevtools.extractors.keywordurl import KeywordURLExtractor
from privacyscanner.utils import FAKE_UA

from urllib.request import urlopen, Request
from urllib.parse import urlparse, urlsplit, urljoin, quote
from bs4 import BeautifulSoup

_GOOGLE_TEMPLATE = 'https://www.google.com/search?q={}&hl={}'
# https://duckduckgo.com/params
_DUCKDUCKGO_TEMPLATE = 'https://duckduckgo.com/html/?q={}&kl={}&kz=-1&kf=-1'

# TODO: it seems these are usually english / en-us policies. Not bad per-se, just sth 2 keep in mind.
#       (these seem to be somewhat curated)
_TRACKER_RADAR_PRIVACY_POLICIES_URL = \
    'https://github.com/duckduckgo/tracker-radar/raw/master/build-data/static/privacy_policies.json'
_tracker_radar_privacy_policies = None


class PrivacyPolicyURLExtractor(KeywordURLExtractor):
    # parts from github.com/cliqz-oss/privacy-bot/blob/master/privacy_bot/mining/find_policies.py
    KEYWORDS = {'privacy policy': 0, 'datenschutzerklärung': 0,
                'datenschutzbestimmungen': 0,
                'mentions-legales': 0, 'conditions-generales': 0,
                'mentions légales': 0, 'conditions générales': 0,
                'termini-e-condizioni': 0,
                'privacy statement': 1,
                'datenschutz': 1,
                'privacy': 2,
                'legal': 3,
                'confidential': 4,
                'ihre daten': 5}
    LANG_SEARCH_TERMS = {
        'en': 'Privacy Policy',
        'de': 'Datenschutzerklärung',
        'fr': 'mentions légales',
        'es': 'conditions générales',
        'it': 'termini-e-condizioni'
    }
    RESULT_KEY = 'privacy_policy_url'

    def extract_information(self):
        best_candidate, candidates = super(PrivacyPolicyURLExtractor, self).extract_information()

        self._load_policy_urls()

        scan_site = parse_domain(self.result['site_url'])
        alt_policy_url = None
        # TODO: check idna
        for name, entry in self.tracker_radar_privacy_policies.items():
            url = entry.get('url')
            if not url:
                # sometimes 'url' does not exists -> just use the policy url's registered domain
                url = entry.get('privacyPolicy') or None

            if url:
                parsed_url = parse_domain(url)
                if parsed_url.registered_domain == scan_site.registered_domain:
                    alt_policy_url = entry.get('privacyPolicy') or None
            # TODO: add name matching, e.g. from SSL certificate

        if best_candidate and alt_policy_url:
            split_alt_policy_url = urlsplit(alt_policy_url)
            if not any((split_alt_policy_url.path, split_alt_policy_url.query, split_alt_policy_url.fragment)):
                return  # looks like wrong data in dataset

            split_keyword_url = urlsplit(best_candidate.url)
            if split_keyword_url.netloc == split_alt_policy_url.netloc \
                    and split_keyword_url.path == split_alt_policy_url.path:
                # our keyword_url (roughly) matches the dataset
                return  # prefer our version (could have regional query component, etc.)

            # TODO: only consider high priority match good vs dataset (too bad href crawling)
            if not any(keyword.replace(' ', '-') in best_candidate.url for keyword in self.KEYWORDS.keys()):
                # our URL looks kind'a bad; use the other one
                self.logger.info("Chose dataset derived policy url %s over url %s found via keyword '%s' (prio: %s)",
                                 alt_policy_url, best_candidate.url, best_candidate.keyword, best_candidate.priority)
                self.result[self.RESULT_KEY] = alt_policy_url
                try:
                    del self.result[self.RESULT_KEY + '_keyword']
                except KeyError:
                    pass

            return
        elif best_candidate:
            return
        elif alt_policy_url:
            self.result[self.RESULT_KEY] = alt_policy_url
            return

        # as a last resort, try a websearch
        _, netloc, _, _, _ = urlsplit(self.result['final_url'])
        search_term = self.LANG_SEARCH_TERMS.get(self.result['language'])
        if not search_term:
            return
        search_term = 'site:{} {}'.format(netloc, search_term)
        self.logger.info("Websearch for privacy policy of %s: %s", netloc, search_term)
        search_term = quote(search_term)
        url = _GOOGLE_TEMPLATE.format(search_term, self.result['language'])
        with urlopen(Request(url, headers={'User-Agent': FAKE_UA})) as r:
            html = r.read()
        # try to parse the results
        soup = BeautifulSoup(html, features='html.parser')
        results = soup.select(selector='div.g', limit=10)
        site_reg_domain = parse_domain(self.result['site_url']).registered_domain
        final_reg_domain = parse_domain(self.result['final_url']).registered_domain
        for result in results:
            a = result.find_next('a', href=True)
            if a:
                href = a['href']
                href_reg_domain = parse_domain(href).registered_domain
                # don't return policies on other domains
                if href_reg_domain == site_reg_domain or href_reg_domain == final_reg_domain:
                    self.logger.info('Websearch found: %s', href)
                    self.result[self.RESULT_KEY] = href
                    break
        else:
            self.logger.error("Websearch for privacy policy url failed")

    def _load_policy_urls(self):
        global _tracker_radar_privacy_policies

        if _tracker_radar_privacy_policies is not None:
            self.tracker_radar_privacy_policies = _tracker_radar_privacy_policies
            return

        with open(self.options['storage_path'] / 'privacy_policies.json') as f:
            self.tracker_radar_privacy_policies = json.load(f)
            _tracker_radar_privacy_policies = self.tracker_radar_privacy_policies

    @staticmethod
    def update_dependencies(options):
        import io
        from privacyscanner.utils import file_is_outdated, download_file

        lookup_file = options['storage_path'] / 'privacy_policies.json'
        if not file_is_outdated(lookup_file, 3600 * 24 * 7):
            return
        buf = io.BytesIO()
        download_url = options.get('tracker_radar_privacy_policies_url', _TRACKER_RADAR_PRIVACY_POLICIES_URL)
        download_file(download_url, buf)
        services_data = json.loads(buf.getvalue())
        with lookup_file.open('w') as f:
            json.dump(services_data, f)
