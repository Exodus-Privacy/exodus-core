import unittest
import xml.etree.ElementTree as ET

from exodus_core.analysis.static_analysis import StaticAnalysis
from exodus_core.analysis.apk_signature import ApkSignature

import logging
logging.disable(logging.CRITICAL)

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

    def test_icon_phash_greater_than_zero(self):
        apps = ['francetv']
        for app in apps:
            with self.subTest(app=app):
                icon_phash = phash('./apks/{}.apk'.format(app))
                self.assertGreater(icon_phash, 0)

    def test_icon_similarity_same_app(self):
        sa = StaticAnalysis()
        apps = ['braiar', 'whatsapp']
        for app in apps:
            with self.subTest(app=app):
                icon_phash = phash('./apks/{}.apk'.format(app))
                diff = sa.get_icon_similarity(icon_phash, icon_phash)
                self.assertEqual(diff, 1.0)

    def test_icon_similarity_different_app(self):
        sa = StaticAnalysis()
        phash_1 = phash('./apks/braiar.apk')
        phash_2 = phash('./apks/whatsapp.apk')
        diff_1 = sa.get_icon_similarity(phash_1, phash_2)
        diff_2 = sa.get_icon_similarity(phash_2, phash_1)

        self.assertEqual(diff_1, 0.5390625)
        self.assertEqual(diff_2, 0.5390625)

    def test_icon_similarity_different_similarities(self):
        sa = StaticAnalysis()
        phash_1 = phash('./apks/braiar.apk')
        phash_2 = phash('./apks/whatsapp.apk')
        phash_3 = phash('./apks/hsbc.apk')
        diff_1 = sa.get_icon_similarity(phash_1, phash_3)
        diff2 = sa.get_icon_similarity(phash_2, phash_3)
        self.assertNotEqual(diff_1, diff2)

    def test_app_uid(self):
        apps = [
            {'name': 'braiar', 'uid': '31BE732147F50EA10063BEACFAB2B4D6E0EEFC32'},
            {'name': 'whatsapp', 'uid': 'F799956E176E259FC28EB51AAD2E3519C9033619'},
            {'name': 'hsbc', 'uid': 'E3B4E87A002A37436CC6B008D3B43C0DB1A4FE13'},
            {'name': 'instapaper', 'uid': '64B99DBA34AFBC3709F75871837465892DF31771'},
            {'name': 'blooddonation', 'uid': '775AFB467E4EF556A42B28181A70B79BA67B4497'},
        ]
        for app in apps:
            with self.subTest(app=app['name']):
                uid = ApkSignature('./apks/{}.apk'.format(app['name'])).app_uid
                self.assertEqual(uid, app['uid'])

    def test_list_classes(self):
        apps = [
            {'name': 'braiar', 'nb_classes': 3896},
            {'name': 'whatsapp', 'nb_classes': 5457},
            {'name': 'hsbc', 'nb_classes': 7481},
            {'name': 'instapaper', 'nb_classes': 2676},
        ]
        for app in apps:
            with self.subTest(app=app['name']):
                classes = list_classes('./apks/{}.apk'.format(app['name']))
                self.assertIsNotNone(classes)
                self.assertEqual(len(classes), app['nb_classes'])

    def test_embedded_trackers(self):
        apps = [
            {'name': 'braiar', 'nb_trackers': 1},
            {'name': 'whatsapp', 'nb_trackers': 1},
            {'name': 'hsbc', 'nb_trackers': 3},
        ]
        for app in apps:
            with self.subTest(app=app['name']):
                apps = list_trackers('./apks/{}.apk'.format(app['name']))
                self.assertIsNotNone(apps)
                self.assertEqual(len(apps), app['nb_trackers'])

    def test_version_code(self):
        apps = [
            {'name': 'braiar', 'version': 13},
            {'name': 'whatsapp', 'version': 451987},
            {'name': 'hsbc', 'version': 61},
        ]
        for app in apps:
            with self.subTest(app=app['name']):
                version = version_code('./apks/{}.apk'.format(app['name']))
                self.assertIsNotNone(version)
                self.assertEqual(int(version), app['version'])


ANDROID_NS = '{http://schemas.android.com/apk/res/android}'


class FakeApk:
    """Minimal APK stand-in exposing an AndroidManifest XML tree."""

    def get_android_manifest_xml(self):
        def perm(tag, name):
            element = ET.Element(tag)
            element.set(ANDROID_NS + 'name', name)
            return element

        root = ET.Element('manifest')
        root.append(perm('uses-permission',
                         'android.permission.ACCESS_NETWORK_STATE'))
        root.append(perm('uses-permission-sdk-23',
                         'android.permission.FOREGROUND_SERVICE'))
        root.append(perm('uses-permission-sdk-23',
                         'android.permission.FOREGROUND_SERVICE_CAMERA'))
        root.append(perm('uses-permission-sdk-m',
                         'android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS'))
        # A duplicate declaration must not be reported twice.
        root.append(perm('uses-permission',
                         'android.permission.ACCESS_NETWORK_STATE'))
        return root


class TestPermissions(unittest.TestCase):

    def setUp(self):
        self.sa = StaticAnalysis()
        self.sa.apk = FakeApk()

    def test_get_permissions_returns_plain_and_sdk_23(self):
        perms = self.sa.get_permissions()
        self.assertIn('android.permission.ACCESS_NETWORK_STATE', perms)
        self.assertIn('android.permission.FOREGROUND_SERVICE', perms)
        self.assertIn('android.permission.FOREGROUND_SERVICE_CAMERA', perms)

    def test_get_permissions_returns_sdk_m(self):
        perms = self.sa.get_permissions()
        self.assertIn('android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS',
                      perms)

    def test_get_permissions_deduplicates(self):
        perms = self.sa.get_permissions()
        self.assertEqual(len(perms), 4)
        self.assertEqual(perms.count('android.permission.ACCESS_NETWORK_STATE'), 1)

    def test_get_permissions_preserves_manifest_order(self):
        perms = self.sa.get_permissions()
        self.assertEqual(perms[0], 'android.permission.ACCESS_NETWORK_STATE')
        self.assertEqual(perms[1], 'android.permission.FOREGROUND_SERVICE')


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestExodus)
    unittest.TextTestRunner(verbosity=2).run(suite)
