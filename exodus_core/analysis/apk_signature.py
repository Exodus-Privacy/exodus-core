from exodus_core.analysis.static_analysis import StaticAnalysis


class ApkSignature:
    def __init__(self, apk_path):
        sa = StaticAnalysis(apk_path)
        self.analysis = sa
        self.apk_path = apk_path
        self.apk_size = sa.get_apk_size()
        self.apk_sha256 = sa.get_sha256()
        self.handle = sa.get_package()
        self.version_code = sa.get_version_code()
        self.version_name = sa.get_version()
        self.app_name = sa.get_app_name()
        self.icon_phash = sa.get_icon_phash()
        self.permissions = sa.get_permissions()
        self.app_uid = sa.get_application_universal_id()
        self.certificates = sa.get_certificates()

    def __str__(self):
        return 'APK: {0}\n' \
               'Size: {1}\n' \
               'SHA256: {2}\n' \
               'Handle: {3}\n' \
               'Version code: {4}\n' \
               'Version name: {5}\n' \
               'App name: {6}\n' \
               'Icon pHash: {7}\n' \
               'App UID: {8}'.format(
                    self.apk_path,
                    self.apk_size,
                    self.apk_sha256,
                    self.handle,
                    self.version_code,
                    self.version_name,
                    self.app_name,
                    self.icon_phash,
                    self.app_uid
                )

    def get_icons_similarity(self, candidate):
        return StaticAnalysis.get_icon_similarity(self.icon_phash, candidate.icon_phash)

    def get_name_similarity(self, candidate):
        import jellyfish

        return {
            # Phonetic distance
            'mra': jellyfish.match_rating_comparison(self.app_name.replace(' ', ''),
                                                     candidate.app_name.replace(' ', '')),
            # String distance
            'jaro': jellyfish.jaro_winkler(self.app_name, candidate.app_name),
        }

    def get_handle_similarity(self, candidate):
        import jellyfish
        return jellyfish.jaro_winkler(self.handle, candidate.handle)

    def get_version_name_similarity(self, candidate):
        import jellyfish
        return jellyfish.jaro_winkler(self.version_name, candidate.version_name)

    def compare(self, candidate):
        is_same_handle = self.handle == candidate.handle
        is_same_name = self.app_name == candidate.app_name
        is_same_version = self.version_code == candidate.version_code
        is_same_size = self.apk_size == candidate.apk_size
        is_same_hash = self.apk_sha256 == candidate.apk_sha256
        is_same_icon = int(self.get_icons_similarity(candidate)) == 1
        is_another_version = is_same_handle and is_same_name and not is_same_version
        is_same_apk = is_same_handle and is_same_name and is_same_version and is_same_size and is_same_hash
        is_perfect_scam = is_same_handle and is_same_name and is_same_version and is_same_size and not is_same_hash

        c = {
            'files': {
                'origin': self.apk_path,
                'candidate': candidate.apk_path,
            },
            'names': {
                'origin': self.app_name,
                'candidate': candidate.app_name,
                'similarity': self.get_name_similarity(candidate),
                'matching': is_same_name
            },
            'handles': {
                'origin': self.handle,
                'candidate': candidate.handle,
                'similarity': self.get_handle_similarity(candidate),
                'matching': is_same_handle
            },
            'icons': {
                'origin': self.icon_phash,
                'candidate': candidate.icon_phash,
                'similarity': self.get_icons_similarity(candidate),
                'matching': is_same_icon
            },
            'version_codes': {
                'origin': self.version_code,
                'candidate': candidate.version_code,
                'matching': is_same_version
            },
            'app_uid': {
                'origin': self.app_uid,
                'candidate': candidate.app_uid,
                'matching': self.app_uid == candidate.app_uid
            },
            'version_names': {
                'origin': self.version_name,
                'candidate': candidate.version_name,
                'matching': self.version_name == candidate.version_name,
                'similarity': self.get_version_name_similarity(candidate),
            },
            'apk_hashes': {
                'origin': self.apk_sha256,
                'candidate': candidate.apk_sha256,
                'matching': is_same_hash
            },
            'result': {
                'is_same_apk': is_same_apk,
                'is_perfect_scam': is_perfect_scam,
            }
        }

        perceived_similarity = (3 * c['names']['similarity']['jaro'] + 2 * c['icons']['similarity'] + 1.5 *
                                c['handles']['similarity']) / 6.5
        if c['names']['similarity']['mra'] is not None:
            perceived_similarity = (3 * c['names']['similarity']['jaro'] + c['names']['similarity']['mra'] + 2 *
                                    c['icons']['similarity'] + 2 * c['handles']['similarity']) / 8.

        c['result']['perceived_similarity'] = perceived_similarity
        c['result']['is_scam'] = perceived_similarity > 0.75 and not is_another_version

        return c
