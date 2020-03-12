from pathlib import Path

from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools import ChromeDevtoolsScanModule
from privacyscanner.scanmodules.chromedevtools.chromescan import ChromeScan, find_chrome_executable
from privacyscanner.scanmodules.chromedevtools.extractors import PrivacyPolicyTextExtractor
from privacyscanner.scanmodules.chromedevtools.utils import TLDEXTRACT_CACHE_FILE, parse_domain
from privacyscanner.utils import set_default_options, file_is_outdated

EXTRACTOR_CLASSES = [PrivacyPolicyTextExtractor]


# TODO: deduplicate stuff from ChromeDevtoolsScanModule
class PrivacyPolicyScanModule(ScanModule):
    name = 'privacypolicy'
    dependencies = ['chromedevtools']
    # `third_party_companies` is only required for online analysis via PrivacyPolicyMissingCompaniesExtractor
    required_keys = ['reachable', 'privacy_policy_url', 'third_party_companies']

    def __init__(self, options):
        if 'chrome_executable' not in options:
            options['chrome_executable'] = find_chrome_executable()
        set_default_options(options, {
            'disable_javascript': False
        })
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)

    def scan_site(self, result, meta):
        if not result['reachable']:
            return
        chrome_scan = ChromeScan(EXTRACTOR_CLASSES)
        debugging_port = self.options.get('start_port', 9222) + meta.worker_id
        content = chrome_scan.scan(result, self.logger, self.options, meta, debugging_port,
                                   result['privacy_policy_url'])
        if not result['reachable']:
            return

    def update_dependencies(self):
        max_age = 14 * 24 * 3600
        cache_file = Path(parse_domain.cache_file)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        if file_is_outdated(cache_file, max_age):
            parse_domain.update(fetch_now=True)
        for extractor_class in EXTRACTOR_CLASSES:
            if hasattr(extractor_class, 'update_dependencies'):
                extractor_class.update_dependencies(self.options)
