import unittest

from exodus_core.analysis.static_analysis import StaticAnalysis
from exodus_core.analysis.apk_signature import ApkSignature

PHASH_SIZE = 16


def phash(apk):
    sa = StaticAnalysis(apk)
    return sa.get_icon_phash()


def save_icon(apk, path):
    sa = StaticAnalysis(apk)
    return sa.save_icon(path)


def icon_path(apk):
    sa = StaticAnalysis(apk)
    return sa.get_icon_path()


def list_classes(apk):
    sa = StaticAnalysis(apk)
    sa.load_trackers_signatures()
    return sa.get_embedded_classes()


def list_trackers(apk):
    sa = StaticAnalysis(apk)
    sa.load_trackers_signatures()
    return sa.detect_trackers()


def version_code(apk):
    sa = StaticAnalysis(apk)
    sa.load_trackers_signatures()
    return sa.get_version_code()


class TestExodus(unittest.TestCase):

    def test_trackers_list(self):
        sa = StaticAnalysis()
        sa.load_trackers_signatures()
        self.assertIsNotNone(sa.signatures)
        self.assertGreater(len(sa.signatures), 70)

    def test_icon_diff(self):
        phash_4 = phash('./apks/nextcloud.apk')
        self.assertEqual(phash_4, 325352301465779383961442563121869825536)
        phash_5 = phash('./apks/francetv.apk')
        self.assertEqual(phash_5, 277543533468213633177527091973989793792)
        phash_1 = phash('./apks/braiar.apk')
        phash_2 = phash('./apks/whatsapp.apk')
        phash_3 = phash('./apks/hsbc.apk')
        sa = StaticAnalysis()
        diff_1 = sa.get_icon_similarity(phash_1, phash_2)
        diff_2 = sa.get_icon_similarity(phash_1, phash_1)
        diff_3 = sa.get_icon_similarity(phash_2, phash_1)
        diff_4 = sa.get_icon_similarity(phash_2, phash_2)
        diff_5 = sa.get_icon_similarity(phash_1, phash_3)
        diff_6 = sa.get_icon_similarity(phash_2, phash_3)
        self.assertEqual(diff_1, 0.609375)
        self.assertEqual(diff_1, diff_3)
        self.assertEqual(diff_2, 1.0)
        self.assertEqual(diff_2, diff_4)
        self.assertNotEqual(diff_5, diff_6)

    def test_app_uid(self):
        self.assertEqual(StaticAnalysis('./apks/braiar.apk').get_application_universal_id(), '38585E1B26493DAB170A08177C6A739D9DB974FE')
        self.assertEqual(StaticAnalysis('./apks/whatsapp.apk').get_application_universal_id(), 'F799956E176E259FC28EB51AAD2E3519C9033619')
        self.assertEqual(StaticAnalysis('./apks/hsbc.apk').get_application_universal_id(), 'E3B4E87A002A37436CC6B008D3B43C0DB1A4FE13')
        self.assertEqual(StaticAnalysis('./apks/instapaper.apk').get_application_universal_id(), '64B99DBA34AFBC3709F75871837465892DF31771')
        self.assertEqual(StaticAnalysis('./apks/blooddonation.apk').get_application_universal_id(), '775AFB467E4EF556A42B28181A70B79BA67B4497')

    def test_list_classes(self):
        # Briar
        classes = list_classes('./apks/braiar.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 3708)
        # Whatsapp
        classes = list_classes('./apks/whatsapp.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 5429)
        # HSBC
        classes = list_classes('./apks/hsbc.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 7431)
        # Instapaper
        classes = list_classes('./apks/instapaper.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 2650)

    def test_embedded_trackers(self):
        # Briar
        trackers = list_trackers('./apks/braiar.apk')
        self.assertIsNotNone(trackers)
        self.assertEqual(len(trackers), 0)
        # Whatsapp
        trackers = list_trackers('./apks/whatsapp.apk')
        self.assertIsNotNone(trackers)
        self.assertEqual(len(trackers), 1)
        # HSBC
        trackers = list_trackers('./apks/hsbc.apk')
        self.assertIsNotNone(trackers)
        self.assertEqual(len(trackers), 2)

    def test_version_code(self):
        # Briar
        version = version_code('./apks/braiar.apk')
        self.assertIsNotNone(version)
        self.assertEqual(int(version), 1620)
        # Whatsapp
        version = version_code('./apks/whatsapp.apk')
        self.assertIsNotNone(version)
        self.assertEqual(int(version), 451987)
        # HSBC
        version = version_code('./apks/hsbc.apk')
        self.assertIsNotNone(version)
        self.assertEqual(int(version), 61)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestExodus)
    unittest.TextTestRunner(verbosity = 2).run(suite)
