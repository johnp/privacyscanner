import time

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.extractors.utils import get_attr

try:
    # textacy has an integrated LRU cache
    from textacy.lang_utils import LangIdentifier
except ImportError:
    LangIdentifier = None

_lang_identifier = None


class LanguageExtractor(Extractor):
    def __init__(self, page, result, logger, options):
        super().__init__(page, result, logger, options)
        self.content = None

    def receive_content(self, content):
        self.content = content

    def extract_information(self):
        node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
        html_node = self.page.tab.DOM.querySelector(nodeId=node_id, selector='html')
        lang = None
        if html_node and 'nodeId' in html_node:
            # should be a ISO-639-1 language tag
            lang = get_attr(self, html_node['nodeId'], 'lang')
            if lang and len(lang) != 2:
                # self.logger.warning("Non ISO-639-1 language code: %s => clipped to 2 characters", lang)
                lang = lang[:2].lower()
            elif lang and len(lang) == 2:
                lang = lang.lower()

        # NLP fallback
        if not lang and LangIdentifier is not None and self.content:
            start = time.time()
            self.logger.info("Falling back to NLP language detection")
            lang = self._get_lang_identifier().identify_lang(self.content)
            self.logger.info("took %s seconds", time.time() - start)
            if lang == 'un':
                lang = None

        if lang:
            self.result['language'] = lang
        elif 'language' not in self.result:
            self.result['language'] = None

    def _get_lang_identifier(self) -> LangIdentifier:
        global _lang_identifier
        if not _lang_identifier:
            _lang_identifier = LangIdentifier(data_dir=self.options['storage_path'] / 'lang_identifier')

        return _lang_identifier

    @staticmethod
    def update_dependencies(options):
        # let textacy handle model download & expiry
        if LangIdentifier is not None:
            lang_identifier = LangIdentifier(data_dir=options['storage_path'] / 'lang_identifier')
            lang_identifier.download()

