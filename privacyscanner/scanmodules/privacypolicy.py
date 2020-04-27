from pathlib import Path

from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools import ChromeDevtoolsScanModule
from privacyscanner.scanmodules.chromedevtools.chromescan import ChromeScan, find_chrome_executable
from privacyscanner.scanmodules.chromedevtools.extractors import PrivacyPolicyLanguageExtractor, \
    PrivacyPolicyTextExtractor, PrivacyPolicyOrganizationsExtractor, PrivacyPolicyThirdPartyAnalysis
from privacyscanner.scanmodules.chromedevtools.utils import TLDEXTRACT_CACHE_FILE, parse_domain
from privacyscanner.utils import set_default_options, file_is_outdated

_EXTRACTOR_CLASSES = [PrivacyPolicyLanguageExtractor, PrivacyPolicyTextExtractor]

_ANALYSIS_CLASSES = [PrivacyPolicyOrganizationsExtractor, PrivacyPolicyThirdPartyAnalysis,]

_EXTRACTOR_CLASSES_WITH_ANALYSIS = [
    *_EXTRACTOR_CLASSES,
    *_ANALYSIS_CLASSES
]


# TODO: deduplicate methods from ChromeDevtoolsScanModule
class PrivacyPolicyFetchModule(ScanModule):
    name = 'privacypolicy'
    dependencies = ['chromedevtools']
    required_keys = ['site_url', 'reachable',
                     # required by PrivacyPolicyTextExtractor
                     'privacy_policy_url',
                     # take site_url language in case the privacy_policy_url doesn't
                     # specify its language
                     'language',
                     ]
    _extractor_classes = _EXTRACTOR_CLASSES

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
        if not result.get('reachable', True) or not result.get('privacy_policy_url'):
            return
        chrome_scan = ChromeScan(self._extractor_classes)
        debugging_port = self.options.get('start_port', 9222) + meta.worker_id
        content = chrome_scan.scan(result, self.logger, self.options, meta, debugging_port,
                                   result['privacy_policy_url'])

    def update_dependencies(self):
        max_age = 14 * 24 * 3600
        cache_file = Path(parse_domain.cache_file)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        if file_is_outdated(cache_file, max_age):
            parse_domain.update(fetch_now=True)
        for extractor_class in self._extractor_classes:
            if hasattr(extractor_class, 'update_dependencies'):
                extractor_class.update_dependencies(self.options)


class PrivacyPolicyScanModule(PrivacyPolicyFetchModule):
    _extractor_classes = _EXTRACTOR_CLASSES_WITH_ANALYSIS

    def __init__(self, options):
        super().__init__(options)
        self.required_keys += [
            # required by PrivacyPolicyThirdPartyAnalysis
            'third_parties',
            'third_parties_disconnectme',
            # soft-required by PrivacyPolicyThirdPartyAnalysis
            'organizations',
            'third_parties_tracker_radar',
        ]


class PrivacyPolicyAnalysisModule(PrivacyPolicyScanModule):
    _extractor_classes = _ANALYSIS_CLASSES
