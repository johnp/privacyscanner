from collections import defaultdict
from itertools import chain
from typing import Dict, List, Set

from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor


# TODO: would aho-corasick be worth it?
class PrivacyPolicyThirdPartyAnalysis(Extractor):

    def extract_information(self):
        self.result['privacy_policy_analysis'] = None
        if 'privacy_policy' not in self.result or not self.result['privacy_policy']:
            self.logger.error("Missing `privacy_policy` from PrivacyPolicyTextExtractor")
            return
        if 'third_parties' not in self.result:
            self.logger.error("Missing `'third_parties': 'fqdns': [...]` from ThirdPartyExtractor")
            return
        has_disconnect = bool(self.result.get('third_parties_disconnectme'))
        has_whotracksme = bool(self.result.get('organizations'))
        has_tracker_radar = bool(self.result.get('third_parties_tracker_radar'))
        if not has_disconnect and not has_whotracksme and not has_tracker_radar:
            self.logger.info("No organizations => Nothing to do")  # TODO: remove logging
            return
        if not has_disconnect:
            self.logger.info("Missing `third_parties_disconnectme` from DisconnectmeExtractor")
        if not has_whotracksme:
            self.logger.info("Missing `organizations` from WhotracksmeExtractor")
        if not has_tracker_radar:
            self.logger.info("Missing `third_parties_tracker_radar` from TrackerRadarExtractor")

        privacy_policy = self.result['privacy_policy']
        privacy_policy_casefold = self.result['privacy_policy'].casefold()

        missing: Dict[str, Set[str]] = defaultdict(set)
        mentioned: Dict[str, Set[str]] = defaultdict(set)
        unattributed_fqdns = []

        if has_disconnect:
            for category, companies in self.result['third_parties_disconnectme']['category_company_fqdns'].items():
                for company, fqdns in companies.items():
                    if self._is_mentioned(company, privacy_policy, privacy_policy_casefold):
                        mentioned[company].update(fqdns)
                    else:
                        missing[company].update(fqdns)

        if has_whotracksme:
            for fqdn, identifier in self.result['organizations']['domains'].items():
                details = self.result['organizations']['details'].get(identifier, None)
                if not details:
                    self.logger.warning("Missing details for identifier " + identifier)
                    continue
                organization = details['name']
                if self._is_mentioned(organization, privacy_policy, privacy_policy_casefold):
                    mentioned[organization].add(fqdn)
                else:
                    missing[organization].add(fqdn)

        if has_tracker_radar:
            # TODO: tracker-radar also has a 'build-data/generated/domain_map.json' and
            #       `build-data/generated/entity_map.json' file which contain aliases for
            #       entities that we could also search for, but we have to check how they
            #       were collected first and why they are only in `build-data `and not in
            #       the advertised/documented files.
            # ref: https://github.com/duckduckgo/tracker-radar-detector/search?q=aliases
            for owner, details in self.result['third_parties_tracker_radar']['owners'].items():
                if self._is_mentioned(owner, privacy_policy, privacy_policy_casefold) or \
                        self._is_mentioned(details['displayName'], privacy_policy, privacy_policy_casefold):
                    mentioned[owner].update(details['fqdns'])
                else:
                    missing[owner].update(details['fqdns'])

        # TODO: consider stemming organizations or using a (prefix-only? ) similarity measure
        #       to reduce false positives even further. tracker-radar has a common suffixes file.

        # check if same fqdn is in mentioned and in missing, e.g. due to different organization mapping
        #  => organization is considered mentioned and fqdns are moved
        for org, fqdns in missing.copy().items():
            for fqdn in fqdns:
                for org2, fqdns_mentioned in mentioned.items():
                    if fqdn in fqdns_mentioned:
                        if org in missing:
                            del missing[org]
                        mentioned[org2].update(fqdns)
                        break

        if not self.result.get('privacy_policy_analysis'):
            self.result['privacy_policy_analysis'] = dict()
        # no set serializer yet :/
        self.result['privacy_policy_analysis']['missing'] = {k: list(v) for k, v in missing.items()}
        self.result['privacy_policy_analysis']['mentioned'] = {k: list(v) for k, v in mentioned.items()}

        for fqdn in self.result['third_parties'].get('fqdns', []):
            if fqdn not in chain(chain.from_iterable(self.result['privacy_policy_analysis']['missing'].values()),
                                 chain.from_iterable(self.result['privacy_policy_analysis']['mentioned'].values())):
                unattributed_fqdns.append(fqdn)

        self.result['privacy_policy_analysis']['unattributed_third_party_fqdns'] = unattributed_fqdns
        self.result.mark_dirty('privacy_policy_analysis')

    def _is_mentioned(self, needle, haystack, haystack_casefold) -> bool:
        if not needle:
            return False
        # TODO: needle is None, because bad tracker_radar data
        # don't casefold very short company names (chance of false matches too high)
        return (needle.casefold() in haystack_casefold) if len(needle) > 3 else (needle in haystack)
