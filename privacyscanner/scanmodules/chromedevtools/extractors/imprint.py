from .keywordurl import KeywordURLExtractor


class ImprintExtractor(KeywordURLExtractor):
    KEYWORDS = {'imprint': 0, 'impressum': 0, 'contact': 1, 'kontakt': 1,
                'about us': 2, 'über uns': 2, 'about': 5}
    RESULT_KEY = 'imprint_url'
