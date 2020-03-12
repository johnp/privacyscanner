from .keywordurl import KeywordURLExtractor


class PrivacyPolicyURLExtractor(KeywordURLExtractor):
    KEYWORDS = ['Privacy Policy', 'Datenschutz', 'Privacy', 'Ihre Daten']
    RESULT_KEY = 'privacy_policy_url'
