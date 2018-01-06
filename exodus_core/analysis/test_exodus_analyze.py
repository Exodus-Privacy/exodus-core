import unittest

from exodus_core.analysis.static_analysis import StaticAnalysis


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

    def test_list_classes(self):
        # Briar
        classes = list_classes('./apks/braiar.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 198248)
        # Whatsapp
        classes = list_classes('./apks/whatsapp.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 199325)
        # HSBC
        classes = list_classes('./apks/hsbc.apk')
        self.assertIsNotNone(classes)
        self.assertEqual(len(classes), 200521)

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
        self.assertEqual(len(trackers), 1)

    def test_version_code(self):
        # Briar
        version = version_code('./apks/braiar.apk')
        self.assertIsNotNone(version)
        self.assertEqual(int(version), 13)
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
