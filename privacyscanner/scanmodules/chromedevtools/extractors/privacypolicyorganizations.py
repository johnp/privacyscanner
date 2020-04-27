from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor

from functools import lru_cache

import time
import spacy

_nlp_en = None


# TODO: Grounding using Entity Linking: https://spacy.io/usage/linguistic-features#entity-linking
#       One could use public data of companies / organizations to create such a KB
class PrivacyPolicyOrganizationsExtractor(Extractor):
    """
        Extract organizations mentioned in a privacy policy using named-entity recognition.
        This uses the small ("sm") spaCy models, but those have good enough NER accuracy and
        are reasonably fast. A custom, domain-specific model would likely be superior though.
    """
    # TODO: consider removing this and improving the loading exception handling to detect
    #       this condition and dynamically re-raise a "Non-supported language" exception.
    _SUPPORTED_LANGUAGES = ['en', 'de', 'fr', 'es', 'pt', 'it', 'nl', 'el',
                            'nb', 'lt', 'xx']

    def extract_information(self):
        self.logger.info('PrivacyPolicyOrganizationsExtractor')
        start = time.time()
        if not self.result.get('privacy_policy'):
            self.logger.error("Missing `privacy_policy` for PrivacyPolicyOrganizationsExtractor")
            self.result['privacy_policy_organizations'] = None
            return

        # fallback to multi-language model on unknown language
        lang = self.result.get('privacy_policy_language', None)
        if not lang:
            lang = self.result.get('language', None)
        if not lang:
            lang = 'xx'
            self.logger.warning("Fallback to multi-language model on site: %s",
                                self.result['privacy_policy_url'])

        if lang not in self._SUPPORTED_LANGUAGES:
            self.logger.warning("Unsupported spaCy language: " + lang)
            return

        try:
            nlp = self._load_spacy(lang)
            if not nlp:
                self.result['privacy_policy_organizations'] = None
                return
        except (OSError, AttributeError) as e:
            self.logger.exception("Error loading spaCy language model %s:\n%s", lang, str(e))
            return
        doc = nlp(self.result['privacy_policy'])
        orgs = set(ent.text for ent in doc.ents if ent.text and ent.label_ == 'ORG')

        self.result['privacy_policy_organizations'] = sorted(orgs)
        self.result['privacy_policy_organizations_model'] = nlp.meta.get('name')
        self.logger.info('PrivacyPolicyOrganizationsExtractor: %.3f s', time.time() - start)

    # TODO: cache more/all models globally by moving this into its own module
    def _load_spacy(self, language):
        global _nlp_en  # always keep the english version in cache

        if language == 'en':
            if not _nlp_en:
                _nlp_en = self.__load_spacy_any(language)
            return _nlp_en
        return self.__load_spacy_any(language)

    # cache any other languages by LRU scheme
    @lru_cache(maxsize=4)
    def __load_spacy_any(self, language):
        try:
            nlp = spacy.load(language)
        except (OSError, IOError, AttributeError):
            spacy.cli.download(language)
            try:
                nlp = spacy.load(language)
            except (OSError, IOError, AttributeError) as e:
                self.logger.exception("Error loading spaCy language model %s:\n%s", e)
                return None
        return nlp

    @staticmethod
    def update_dependencies(options):
        # let spaCy handle model download and expiry via pip
        # TODO: these are downloaded into the virtualenv instead of the storage_path
        #       we could pass `-t / --target` via `pip_args` to install to storage_path
        spacy.cli.download('en')
        spacy.cli.download('de')
        # TODO: should we download more models eagerly?
        # TODO: re-consider "xx_ent_wiki_sm" fallback


if __name__ == '__main__':
    """
        Runs the given text file or all text files in the given folder through
        Named-entity recognition for organizations and exports the results to
        a .json file with the same base file name.
    """

    import sys
    import json
    from pathlib import Path
    if len(sys.argv) < 3:
        print("./privacypolicyorganizations.py [text_file_folder] [language]")
        exit(-1)

    path = Path(sys.argv[1])
    if not path.exists():
        print("Path does not exist", file=sys.stderr)
        exit(-2)

    nlp = spacy.load(sys.argv[2])

    def process_file(file):
        out = file.with_suffix('json')
        if out.exists():
            print("Output file already exists", file=sys.stderr)
            exit(-3)

        with open(file) as f:
            text = f.read()
        doc = nlp(text)
        orgs = set(ent.text for ent in doc.ents if ent.text and ent.label_ == 'ORG')

        with open(file.with_suffix('json'), 'w') as f:
            json.dump(list(orgs), f)

    if path.is_dir():
        files = path.iterdir()
    else:
        files = (path for path in [path])

    for f in files:
        process_file(f)
