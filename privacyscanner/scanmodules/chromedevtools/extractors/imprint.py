from .keywordurl import KeywordURLExtractor


class ImprintExtractor(KeywordURLExtractor):
    KEYWORDS = ['imprint', 'impressum', 'contact', 'kontakt', 'about us', 'über uns']
    RESULT_KEY = 'imprint_url'
