import time

from pychrome import CallMethodException

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.extractors.utils import get_attr

try:
    # textacy has an integrated LRU cache
    from textacy.lang_utils import LangIdentifier
    from bs4 import BeautifulSoup
except ImportError:
    LangIdentifier = None

_lang_identifier = None


class LanguageExtractor(Extractor):
    RESULT_KEY = 'language'

    def __init__(self, page, result, logger, options):
        super().__init__(page, result, logger, options)
        self.content = None

    def receive_content(self, content):
        self.content = content

    def extract_information(self):
        # check html lang
        lang = self._find_lang_attr_by_selector('html')

        # check head lang
        if not lang:
            lang = self._find_lang_attr_by_selector('head')

        # check body lang
        if not lang:
            lang = self._find_lang_attr_by_selector('body')

        # NLP fallback
        if not lang and LangIdentifier is not None and self.content:
            start = time.time()
            self.logger.info("Falling back to NLP language detection")
            soup = BeautifulSoup(self.content)
            text = soup.get_text(strip=True)
            lang = self._get_lang_identifier().identify_lang(text)
            self.logger.info("took %s seconds", time.time() - start)
            if lang == 'un':
                lang = None

        if lang:
            self.result[self.RESULT_KEY] = lang
        elif self.RESULT_KEY not in self.result:
            self.result[self.RESULT_KEY] = None

    def _find_lang_attr_by_selector(self, selector):
        try:
            node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
            selected_node = self.page.tab.DOM.querySelector(nodeId=node_id, selector=selector)
        except CallMethodException:
            selected_node = None
        lang = None
        if selected_node and 'nodeId' in selected_node:
            # should be a ISO-639-1 language tag
            lang = get_attr(self, selected_node['nodeId'], 'lang')
            if lang and len(lang) != 2:
                # self.logger.warning("Non ISO-639-1 language code: %s => clipped to 2 characters", lang)
                lang = lang[:2].lower()
            elif lang and len(lang) == 2:
                lang = lang.lower()
        return lang

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


class PrivacyPolicyLanguageExtractor(LanguageExtractor):
    RESULT_KEY = 'privacy_policy_language'
