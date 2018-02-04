import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.request
import zipfile
from collections import namedtuple
from hashlib import sha256
from tempfile import NamedTemporaryFile
from threading import Thread

from future.moves import sys

from exodus_core.analysis.certificate import Certificate

PHASH_SIZE = 8

from androguard.core.bytecodes.apk import APK


class StaticAnalysis:
    def __init__(self, apk_path = None):
        self.apk = None
        self.apk_path = apk_path
        self.signatures = None
        self.classes = None
        if apk_path is not None:
            self.load_apk()

    def load_trackers_signatures(self):
        """
        Load trackers signatures from the official Exodus database.
        :return: a dictionary containing signatures.
        """
        self.signatures = []
        exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers"
        with urllib.request.urlopen(exodus_url) as url:
            data = json.loads(url.read().decode())
            for e in data['trackers']:
                self.signatures.append(namedtuple('tracker', data['trackers'][e].keys())(*data['trackers'][e].values()))

    def load_apk(self):
        """
        Load the APK file.
        """
        if self.apk is None:
            self.apk = APK(self.apk_path)

    def get_embedded_classes(self):
        """
        Get the list of Java classes embedded into all DEX files.
        :return: array of Java classes names as string
        """
        if self.classes is not None:
            return self.classes
        # start = time.time()
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                apk_zip.extractall(tmp_dir)
            dexdump = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dexdump', 'dexdump')
            cmd = '%s %s/classes*.dex | perl -n -e\'/[A-Z]+((?:\w+\/)+\w+)/ && print "$1\n"\'|sort|uniq' % (
                dexdump, tmp_dir)
            try:
                self.classes = subprocess.check_output(cmd, stderr = subprocess.STDOUT, shell = True,
                                                       universal_newlines = True).splitlines()
                # end = time.time()
                # print('get_embedded_classes took %.2f sec.' % (end - start))
                return self.classes
            except subprocess.CalledProcessError:
                raise Exception('Unable to decode the APK')

    def detect_trackers_in_list(self, class_list):
        """
        Detect embedded trackers in the provided classes list.
        :return: list of embedded trackers
        """
        # start = time.time()
        if self.signatures is None:
            self.load_trackers_signatures()

        def _detect_tracker(tracker, class_list, results, i):
            for clazz in class_list:
                m = re.search(tracker.code_signature, clazz)
                if m is not None:
                    results[i] = tracker
            return None

        threads = [None] * len(self.signatures)
        results = [None] * len(self.signatures)
        i = 0
        for tracker in self.signatures:
            if len(tracker.code_signature) > 3:
                threads[i] = Thread(target = _detect_tracker, args = (tracker, class_list, results, i))
                threads[i].start()
                i += 1

        for j in range(i):
            threads[j].join()

        # end = time.time()
        # print('detect_trackers_in_list took %.2f sec.' % (end - start))
        return [t for t in results if t is not None]

    def detect_trackers(self, class_list_file = None):
        """
        Detect embedded trackers.
        :return: list of embedded trackers
        """
        if self.signatures is None:
            self.load_trackers_signatures()
        if class_list_file is None:
            return self.detect_trackers_in_list(self.get_embedded_classes())
        else:
            with open(class_list_file, 'r') as classes_file:
                classes = classes_file.readlines()
                return self.detect_trackers_in_list(classes)

    def get_version(self):
        """
        Get the application version name
        :return: version name
        """
        return self.apk.get_androidversion_name()

    def get_version_code(self):
        """
        Get the application version code
        :return: version code
        """
        return self.apk.get_androidversion_code()

    def get_permissions(self):
        """
        Get application permissions
        :return: application permissions list
        """
        return self.apk.get_permissions()

    def get_app_name(self):
        """
        Get application name
        :return: application name
        """
        return self.apk.get_app_name()

    def get_package(self):
        """
        Get application package
        :return: application package
        """
        return self.apk.get_package()

    def get_libraries(self):
        """
        Get application libraries
        :return: application libraries list
        """
        return self.apk.get_libraries()

    def get_icon_path(self):
        """
        Get the icon path in the ZIP archive
        :return: icon path in the ZIP archive
        """
        return self.apk.get_app_icon()

    def save_icon(self, path):
        """
        Extract the icon from the ZIP archive and save it at the given path
        :param path: destination path of the icon
        :return: destination path of the icon, None in case of error
        """
        icon = self.get_icon_path()
        if icon is None:
            return None

        with zipfile.ZipFile(self.apk_path) as z:
            with open(path, 'wb') as f:
                f.write(z.read(icon))
                return path

    def get_icon_phash(self):
        """
        Get the perceptual hash of the icon
        :return: the perceptual hash, None in case of error
        """
        import dhash
        from PIL import Image
        dhash.force_pil()  # Force PIL
        with NamedTemporaryFile() as ic:
            path = self.save_icon(ic.name)
            if path is None:
                return None
            image = Image.open(ic.name)
            row, col = dhash.dhash_row_col(image, size = PHASH_SIZE)
            return row << (PHASH_SIZE * PHASH_SIZE) | col

    @staticmethod
    def get_icon_similarity(phash_origin, phash_candidate):
        """
        Get icons similarity score [0,1.0]
        :param phash_origin: original icon
        :param phash_candidate: icon to be compared
        :return: similarity score [0,1.0]
        """
        import dhash
        diff = dhash.get_num_bits_different(phash_origin, phash_candidate)
        return 1 - 1. * diff / (PHASH_SIZE * PHASH_SIZE * 2)

    def get_application_universal_id(self):
        parts = [self.get_package()]
        for c in self.get_certificates():
            parts.append(c.fingerprint)
        return hashlib.sha1(' '.join(parts).encode('utf-8')).hexdigest().upper()

    def get_certificates(self):
        certificates = []
        signs = self.apk.get_signature_names()
        for s in signs:
            with zipfile.ZipFile(self.apk_path) as z:
                with tempfile.NamedTemporaryFile(delete = False) as f:
                    f.write(z.read(s))
                    f.flush()
                    c = Certificate(f.name)
                    certificates.append(c)
        return certificates

    def get_apk_size(self):
        """
        Get the APK file size in bytes
        :return: APK file size
        """
        return os.path.getsize(self.apk_path)

    def get_sha256(self):
        """
        Get the sha256sum of the APK file
        :return: hex sha256sum
        """
        BLOCKSIZE = 65536
        hasher = sha256()
        with open(self.apk_path, 'rb') as apk:
            buf = apk.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = apk.read(BLOCKSIZE)
        return hasher.hexdigest()

    def save_embedded_classes_in_file(self, file_path):
        """
        Save list of embedded classes in file.
        :param file_path: file to write
        """
        with open(file_path, 'w+') as f:
            f.write('\n'.join(self.get_embedded_classes()))

    def print_apk_infos(self):
        """
        Print APK information
        """
        print("=== Information")
        print('- APK path: %s' % self.apk_path)
        print('- APK sum: %s' % self.get_sha256())
        print('- App version: %s' % self.get_version())
        print('- App version code: %s' % self.get_version_code())
        print('- App UID: %s' % self.get_application_universal_id())
        print('- App name: %s' % self.get_app_name())
        print('- App package: %s' % self.get_package())
        print('- App permissions: %s' % len(self.get_permissions()))
        for p in self.get_permissions():
            print('    - %s' % p)
        print('- App libraries: %s' % len(self.get_libraries()))
        for l in self.get_libraries():
            print('    - %s' % l)
        certificates = self.get_certificates()
        print('- Certificates: %s' % len(certificates))
        for c in certificates:
            print('    - %s' % c)

    def print_embedded_trackers(self):
        """
        Print detected trackers
        """
        trackers = self.detect_trackers()
        print('=== Found trackers: {0}'.format(len(trackers)))
        for t in trackers:
            print(' - %s' % t.name)


if __name__ == '__main__':
    apk_path = sys.argv[1]
    sa = StaticAnalysis(apk_path)
    sa.print_apk_infos()
    sa.print_embedded_trackers()
