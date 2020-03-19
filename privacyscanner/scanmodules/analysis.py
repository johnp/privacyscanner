import logging
from pathlib import Path

from privacyscanner.scanmodules import ScanModule
from privacyscanner.scanmodules.chromedevtools.extractors import PrivacyPolicyOrganizationsExtractor, \
    PrivacyPolicyThirdPartyAnalysis, DisconnectmeExtractor, WhotracksmeExtractor, TrackerRadarExtractor
from privacyscanner.scanmodules.chromedevtools.utils import TLDEXTRACT_CACHE_FILE, parse_domain
from privacyscanner.utils import file_is_outdated

# TODO: move somewhere else and rename to "Analyzer" or similar, such that
#       we don't have the receive_log / register_javascript methods
EXTRACTOR_CLASSES = [
    DisconnectmeExtractor,
    WhotracksmeExtractor,
    TrackerRadarExtractor,
    PrivacyPolicyOrganizationsExtractor,
    PrivacyPolicyThirdPartyAnalysis
]


class AnalysisScanModule(ScanModule):
    """
    A ScanModule that just performs offline processing & analysis of data from previous
    scan modules.
    # TODO: this is not completely finished yet
    """

    name = 'analysis'
    dependencies = []
    required_keys = ['site_url', 'final_url', 'language',
                     'privacy_policy',
                     'third_parties',
                     ]
    reuse_results = True

    def __init__(self, options):
        super().__init__(options)
        cache_file = self.options['storage_path'] / TLDEXTRACT_CACHE_FILE
        parse_domain.cache_file = str(cache_file)

    def scan_site(self, result, meta):
        logger = logging.Logger(self.__class__.name)
        for extractor_class in EXTRACTOR_CLASSES:
            extractor = extractor_class(None, result, logger, self.options)
            extractor.extract_information()

    def update_dependencies(self):
        max_age = 14 * 24 * 3600
        cache_file = Path(parse_domain.cache_file)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        if file_is_outdated(cache_file, max_age):
            parse_domain.update(fetch_now=True)
        for extractor_class in EXTRACTOR_CLASSES:
            if hasattr(extractor_class, 'update_dependencies'):
                extractor_class.update_dependencies(self.options)
