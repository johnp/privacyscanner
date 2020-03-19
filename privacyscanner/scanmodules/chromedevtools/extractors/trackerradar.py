import idna
import io
import json
from collections import defaultdict

from privacyscanner.scanmodules.chromedevtools.utils import parse_domain, walk_fqdn_until_public_suffix
from privacyscanner.scanmodules.chromedevtools.extractors.base import Extractor
from privacyscanner.utils import download_file, file_is_outdated, extract_tar

from functools import lru_cache

_TRACKER_RADAR_URL = 'https://github.com/duckduckgo/tracker-radar/archive/master.tar.gz'
_DATA_BASE_DIR = 'tracker-radar'


# TODO: consider moving tracker_radar loading to a mixin or base class
class TrackerRadarExtractor(Extractor):
    """
        Maps third-party domains to owners and categories using DuckDuckGo's Tracker Radar dataset.
    """

    RESULT_KEY = 'third_parties_tracker_radar'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._data_base_dir = self.options['storage_path'] / _DATA_BASE_DIR

    def extract_information(self):
        if 'third_parties' not in self.result or 'fqdns' not in self.result['third_parties']:
            self.logger.error("Missing `third_parties` or `fqdns`.")
            return

        third_party_owners = {
            'owners': defaultdict(lambda: {
                'name': None,
                'displayName': None,
                'categories': set(),
                'fqdns': [],
            }),
            'unrecognized_fqdns': []
        }

        third_party_domains = self.result['third_parties']['fqdns']
        if third_party_domains and len(third_party_domains) > 0:
            for fqdn in third_party_domains:
                domain_data = self._load_data(fqdn)
                if not domain_data or not domain_data.get('owner'):
                    third_party_owners['unrecognized_fqdns'].append(fqdn)
                    continue
                owner = domain_data['owner'].get('name')
                third_party_owners['owners'][owner]['name'] = owner
                third_party_owners['owners'][owner]['displayName'] = domain_data['owner'].get('displayName')
                third_party_owners['owners'][owner]['fqdns'].append(fqdn)
                third_party_owners['owners'][owner]['categories'].update(domain_data.get('categories'))

            # no set serializer yet :/
            for details in third_party_owners['owners'].values():
                details['categories'] = list(details['categories'])

        # defaultdict doesn't serialize to json properly -> convert to normal dict
        third_party_owners['owners'] = dict(third_party_owners['owners'])
        third_party_owners['unrecognized_fqdns'].sort()

        self.result[self.RESULT_KEY] = third_party_owners
        self.result.mark_dirty(self.RESULT_KEY)

    # TODO: find good maxsize / cache more globally (incl. idna; cache Nones more aggressively?)
    @lru_cache(maxsize=50)
    def _load_data(self, fqdn):
        for fqdn in walk_fqdn_until_public_suffix(fqdn):
            try:
                idna_encoded = fqdn.encode('idna').decode()
                with open(self._data_base_dir / '{}.json'.format(idna_encoded)) as f:
                    data = json.load(f)
                    return data
            except FileNotFoundError as e:
                pass
            except OSError as e:
                self.logger.exception("Error opening tracker-radar data file:\n%s", e)
            except UnicodeError as e:
                self.logger.error("UnicodeError while IDNA encoding %s:\n%s", fqdn, str(e))
                break
                #raise e
        return None

    # TODO: atomic replace of directory on update would be nice...
    #       (for all the extractors really)
    @staticmethod
    def update_dependencies(options):
        import os
        from shutil import rmtree

        target_dir = options['storage_path'] / _DATA_BASE_DIR
        canary = target_dir / 'canary'
        if target_dir.exists():
            if not file_is_outdated(canary, 3600 * 24 * 7) and len(os.listdir(target_dir)) > 10000:
                return
            rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        buf = io.BytesIO()
        download_url = options.get('tracker_radar_url', _TRACKER_RADAR_URL)
        download_file(download_url, buf)
        buf.seek(0)

        def filter_map(members):
            for finfo in members:
                if finfo.name.startswith('tracker-radar-master/domains/'):
                    finfo.name = os.path.basename(finfo.name)
                    yield finfo

        extract_tar(buf, target_dir, filter_map)
        # TODO: it may be worth it to strip some data here to reduce deserialization churn

        if len(os.listdir(target_dir)) <= 1:
            raise Exception("Failed to download or extract TrackerRadar data")
        canary.touch()
