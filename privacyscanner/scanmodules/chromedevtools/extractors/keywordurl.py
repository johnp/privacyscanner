import warnings
from abc import ABCMeta, abstractmethod
from urllib.parse import urlparse

import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.utils import scripts_disabled


ELEMENT_NODE = 1


class KeywordURLExtractor(Extractor, metaclass=ABCMeta):
    @property
    @abstractmethod
    def KEYWORDS(self):
        raise NotImplementedError

    @property
    @abstractmethod
    def RESULT_KEY(self):
        raise NotImplementedError

    def extract_information(self):
        # Disable scripts to avoid DOM changes while searching for the keyword URL.
        with scripts_disabled(self.page.tab, self.options):
            self._extract_keyword_url()

    def _extract_keyword_url(self):
        node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
        links = self.page.tab.DOM.querySelectorAll(nodeId=node_id, selector='a')['nodeIds']
        keyword_link = None

        # Use the browsers search to search for the keywords. For each result,
        # we walk up the DOM until we find an ``a'' element. If this element
        # has an href, this is our keyword link. Otherwise, we look for the
        # next search result.
        for keyword in self.KEYWORDS:
            search = self.page.tab.DOM.performSearch(query=keyword)
            if search['resultCount'] == 0:
                continue
            results = self.page.tab.DOM.getSearchResults(
                searchId=search['searchId'], fromIndex=0, toIndex=search['resultCount'])
            for node_id in results['nodeIds']:
                while node_id is not None:
                    try:
                        node = self.page.tab.DOM.describeNode(nodeId=node_id)['node']
                    except pychrome.CallMethodException:
                        # For some reason, nodes seem to disappear in-between,
                        # so just ignore these cases.
                        break
                    if node['nodeType'] == ELEMENT_NODE and node['nodeName'].lower() == 'a':
                        if not self._is_visible(node_id):
                            break
                        href = self._get_href(node_id)
                        if href:
                            keyword_link = href
                        break
                    node_id = node.get('parentId')
                if keyword_link:
                    break
            if keyword_link:
                break

        # If our browser search does not give results, search more brutally
        # for all links, including those, who are not visible to the user.
        if not keyword_link:
            for link in links:
                try:
                    link_html = self.page.tab.DOM.getOuterHTML(nodeId=link)['outerHTML']
                except pychrome.CallMethodException:
                    # For some reason, nodes seem to disappear in-between,
                    # so just ignore these cases.
                    break
                for order_id, keyword in enumerate(self.KEYWORDS):
                    if keyword in link_html:
                        href = self._get_href(link)
                        if href:
                            keyword_link = href
                            break
                if keyword_link:
                    break

        if keyword_link:
            if keyword_link.startswith('//'):
                p = urlparse(self.result['final_url'])
                keyword_link = '{}:{}'.format(p.scheme, keyword_link)
            elif keyword_link.startswith('/'):
                p = urlparse(self.result['final_url'])
                keyword_link = '{}://{}{}'.format(p.scheme, p.hostname, keyword_link)
            elif keyword_link.startswith(('https://', 'http://')):
                # Nothing to do, already the full URL
                pass
            else:
                base_url = self.result['final_url'].rsplit('/', 1)[0]
                keyword_link = '{}/{}'.format(base_url, keyword_link)
        self.result[self.RESULT_KEY] = keyword_link

    def _get_href(self, node_id):
        attrs = self.page.tab.DOM.getAttributes(nodeId=node_id)['attributes']
        attrs = dict(zip(*[iter(attrs)]*2))
        return attrs.get('href')

    def _is_visible(self, node_id):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.page.tab.DOM.getBoxModel(nodeId=node_id)
            return True
        except pychrome.exceptions.CallMethodException:
            return False
