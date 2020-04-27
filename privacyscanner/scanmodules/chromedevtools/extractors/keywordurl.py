import warnings
from abc import ABCMeta, abstractmethod
from operator import itemgetter
from typing import Union, List, Dict, Set, NamedTuple
from urllib.parse import urlparse

import pychrome

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.scanmodules.chromedevtools.extractors.utils import get_attr
from privacyscanner.scanmodules.chromedevtools.utils import scripts_disabled

ELEMENT_NODE = 1


class Candidate(NamedTuple):
    keyword: str
    priority: int
    url: str


# TODO: Sites with issues:
#       * duckduckgo.com has "Privacy Policy" link in a nav-menu that's invisible to pychrome
#         (and Firefox' "View Source")
#        * youtube.com also doesn't work (sidebar)
class KeywordURLExtractor(Extractor, metaclass=ABCMeta):
    @property
    @abstractmethod
    def KEYWORDS(self) -> Union[Set[str], Dict[str, int]]:
        raise NotImplementedError

    @property
    @abstractmethod
    def RESULT_KEY(self) -> str:
        raise NotImplementedError

    def _top_priority(self) -> int:
        return min(self.KEYWORDS.values()) if isinstance(self.KEYWORDS, Dict) else 0

    def extract_information(self):
        # Disable scripts to avoid DOM changes while searching for the keyword URL.
        with scripts_disabled(self.page.tab, self.options):
            return self._extract_keyword_url()

    def _extract_keyword_url(self):
        if isinstance(self.KEYWORDS, Set):
            keywords = self.KEYWORDS
            priorities = {keyword: index for keyword, index in keywords.items()}
        elif isinstance(self.KEYWORDS, Dict):
            keywords = self.KEYWORDS.keys()
            priorities = self.KEYWORDS
        else:
            self.logger.error("Invalid `KEYWORDS` type: " + type(self.KEYWORDS).__name__)
            return
        top_priority = self._top_priority()
        keyword_url_candidates: List[Candidate] = []

        # Use the browsers search to search for the keywords. For each result,
        # we walk up the DOM until we find an ``a'' element. If this element
        # has an href, this is a keyword link candidate. Then we look for the
        # next search result.
        node_id = self.page.tab.DOM.getDocument()['root']['nodeId']
        links = self.page.tab.DOM.querySelectorAll(nodeId=node_id, selector='a')['nodeIds']
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
                            keyword_url_candidates.append(
                                Candidate(keyword, priorities[keyword], href))
                            # Fast return if we immediately find a top-priority result
                            if priorities[keyword] == top_priority:
                                break
                    node_id = node.get('parentId')
        best_candidate = min(keyword_url_candidates, key=lambda candidate: candidate.priority) \
            if keyword_url_candidates else None

        # If our browser search does not give results or we didn't find a result
        # via the top-priority keyword, search more brutally for all links,
        # including those, who are not visible to the user.
        if not best_candidate or best_candidate.priority != top_priority:
            for link in links:
                try:
                    link_html = self.page.tab.DOM.getOuterHTML(nodeId=link)['outerHTML']
                except pychrome.CallMethodException:
                    # For some reason, nodes seem to disappear in-between,
                    # so just ignore these cases.
                    break
                for keyword in keywords:
                    if keyword in link_html:
                        href = self._get_href(link)
                        if href:
                            # TODO: consider reducing the priority of potentially invisible elements
                            keyword_url_candidates.append(
                                Candidate(keyword, priorities[keyword], href))
            best_candidate = min(keyword_url_candidates, key=itemgetter(1)) \
                if keyword_url_candidates else None

        # TODO: Possible improvements:
        # * fetch each candidate and check page title
        # * sitemap fallback

        if best_candidate:
            keyword, priority, keyword_link = best_candidate
            # TODO: Data shows some relative KeywordURLs (e.g. href='/imprint') that are not normalized
            #       (consider rewriting this with urljoin/urlunsplit)
            if keyword_link.startswith('//'):  # same scheme as document
                p = urlparse(self.result['final_url'])
                keyword_link = '{}:{}'.format(p.scheme, keyword_link)
            elif keyword_link.startswith('/'):  # relative to root
                p = urlparse(self.result['final_url'])
                keyword_link = '{}://{}{}'.format(p.scheme, p.hostname, keyword_link)
            elif keyword_link.startswith(('https://', 'http://')):
                # Nothing to do, already the full URL
                pass
            else:
                # Relative to current URL
                base_url = self.result['final_url'].rsplit('/', 1)[0]
                keyword_link = '{}/{}'.format(base_url, keyword_link)
            self.result[self.RESULT_KEY] = keyword_link
            self.result[self.RESULT_KEY + '_keyword'] = keyword
            #self.logger.info("Found keyword link '%s' for site '%s' via keyword '%s' with priority %s",
            #                 keyword_link, self.result['site_url'], keyword, priority)
        else:
            self.result[self.RESULT_KEY] = None
            self.result[self.RESULT_KEY + '_keyword'] = None
            #self.logger.warning("Could not find keyword link for '%s' on site '%s'",
            #                    str(self.__class__.__name__), self.result['site_url'])
        # return to allow superclasses to implement domain-specific fallback or logic
        return best_candidate, keyword_url_candidates

    def _get_href(self, node_id):
        return get_attr(self, node_id, 'href')

    def _is_visible(self, node_id):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.page.tab.DOM.getBoxModel(nodeId=node_id)
            return True
        except pychrome.exceptions.CallMethodException:
            return False
