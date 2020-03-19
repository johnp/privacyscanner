from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import javascript_evaluate, JavaScriptError
from privacyscanner.utils import download_file, file_is_outdated

from pathlib import Path

# TODO: maybe track stable Firefox's version of Readability.js which is updated regularly and is less likely to
#       break compared to GitHub master:
#   https://hg.mozilla.org/releases/mozilla-release/raw-file/tip/toolkit/components/reader/Readability.js
_READABILITY_JS_URL = \
    'https://raw.githubusercontent.com/mozilla/readability/dc34dfd8fa6d5c17801efbc2e115dc368b7117c8/Readability.js'
_READABILITY_JS_PATH = Path('Readability.js')

_READABILITY_EXTRACT_JS = '''
(function() {
    let article = new Readability(document.cloneNode(true)).parse();

    if (article === null) { // Readability.js failed for some reason
        return JSON.stringify({
            'privacy_policy_title': document.title,
            'privacy_policy_html': document.body.innerHtml,
            'privacy_policy': document.body.innerText,
            'privacy_policy_length': document.body.innerText.length,
            'body_innerText_length': document.body.innerText.length,
            'source': 'document_body_innerText',
        });
    }

    return JSON.stringify({
        // title as identified via Readability.js
        'privacy_policy_title': article.title,
        // .content == .innerHtml (may be used for markup-based extraction)
        'privacy_policy_html': article.content,
        // .textContent may be sub-optimal (innerText may be better, but not exposed via Readability,parse())
        'privacy_policy': article.textContent,
        // respective document lengths to easily identify cases (large mismatch) where Readability may have messed up
        'privacy_policy_length': article.textContent.length,
        // innerText is the closest approximation to the article length (skips inline scripts/css and invisible content)
        'body_innerText_length': document.body.innerText.length,
        // indicates the method used for policy text extraction
        'source': 'Readability.js',
    });
})();
'''.lstrip()

_INNER_TEXT_EXTRACT_JS = '''
(function() {
    return JSON.stringify({
        'privacy_policy_title': document.title,
        'privacy_policy_html': document.body.innerHtml,
        'privacy_policy': document.body.innerText,
        'privacy_policy_length': document.body.innerText.length,
        'body_innerText_length': document.body.innerText.length,
        'source': 'document_body_innerText',
    });
})();
'''


# TODO: consider saving the policy text to a file instead
class PrivacyPolicyTextExtractor(Extractor):

    def extract_information(self):
        if self.options['disable_javascript']:
            return

        try:
            # Stringifying readability.js breaks the JS syntax ("SyntaxError: missing ) after argument list")
            res = javascript_evaluate(self.page.tab, self._readability_extract_js(), False)
        except JavaScriptError as e:
            self.logger.error("JavaScriptError while trying to extract privacy text via Readablity:")
            self.logger.exception(e)
            try:
                res = javascript_evaluate(self.page.tab, _INNER_TEXT_EXTRACT_JS, False)
            except JavaScriptError as e:
                self.logger.error("JavaScriptError while trying to extract privacy policy via document.body.innerText:")
                self.logger.exception(e)
                return

        if res['source'] != "Readability.js":
            self.logger.warning("Fell back to '%s' method for privacy policy text extraction on '%s'.",
                                res['source'], self.result['privacy_policy_url'])
        # TODO: empirically determine a good cut-off value for suspiciously small extracted policy
        elif res['body_innerText_length'] > 0 and res['privacy_policy_length'] / res['body_innerText_length'] < 0.7:
            self.logger.warning(
                "Extracted privacy policy from '%s' is significantly smaller than the website text (%s / %s).",
                self.result['privacy_policy_url'], res['privacy_policy_length'], res['body_innerText_length'])

        self.result['privacy_policy_metadata'] = {
            'title': res['privacy_policy_title'],
            'length': res['privacy_policy_length'],
            'body_innerText_length': res['body_innerText_length'],
            'source': res['source'],
        }
        self.result['privacy_policy'] = res['privacy_policy']

    def _readability_extract_js(self):
        with open(self.options['storage_path'] / 'Readability.js') as f:
            return f.read() + '\n\n' + _READABILITY_EXTRACT_JS

    @staticmethod
    def update_dependencies(options):
        readability_js_file = options['storage_path'] / _READABILITY_JS_PATH
        if not file_is_outdated(readability_js_file, 3600 * 24 * 7):
            return

        download_url = options.get('readability_js_url', _READABILITY_JS_URL)
        with open(readability_js_file, 'wb') as f:
            download_file(download_url, f)
