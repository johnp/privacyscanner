from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor

import textacy
from textacy import TextStats


class PrivacyPolicyMetricsExtractor(Extractor):

    def extract_information(self):
        self.result['privacy_policy_metrics'] = None
        if 'privacy_policy' not in self.result or not self.result['privacy_policy']:
            self.logger.error("Missing `privacy_policy` from PrivacyPolicyTextExtractor")
            return

        doc = textacy.make_spacy_doc(self.result['privacy_policy'], self.result['language'])
        stats = TextStats(doc)
        #  TODO: select readability metric to produce (maybe depending on language)

        self.result['privacy_policy_metrics'] = {
        }

    @staticmethod
    def update_dependencies(options):
        pass
