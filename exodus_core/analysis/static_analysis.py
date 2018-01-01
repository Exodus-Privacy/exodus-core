import json
import os
import re
import subprocess
import tempfile
import urllib.request
import zipfile
from hashlib import sha256

from androguard.core.bytecodes.apk import APK


class StaticAnalysis:
    def __init__(self, apk_path = None):
        self.apk = None
        self.apk_path = apk_path
        self.signatures = None
        if apk_path is not None:
            self.load_apk()

    def load_trackers_signatures(self):
        """
        Load trackers signatures from the official Exodus database.
        :return: a dictionary containing signatures.
        """
        exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers"
        with urllib.request.urlopen(exodus_url) as url:
            data = json.loads(url.read().decode())
            self.signatures = data['trackers']

    def load_apk(self):
        """
        Load the APK file.
        """
        self.apk = APK(self.apk_path)

    def get_embedded_classes(self):
        """
        Get the list of Java classes embedded into all DEX files.
        :return: array of Java classes names as string
        """
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                apk_zip.extractall(tmp_dir)
            dexdump = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dexdump', 'dexdump')
            cmd = '%s %s/classes*.dex | grep "Class descriptor" | cut -d: -f2 | sort | uniq' % (
                dexdump, tmp_dir)
            try:
                out = subprocess.check_output(cmd, stderr = subprocess.STDOUT, shell = True,
                                              universal_newlines = True).splitlines()
                return out
            except subprocess.CalledProcessError:
                raise Exception('Unable to decode the APK')

    def detect_trackers(self):
        """
        Detect embedded trackers.
        """
        if self.signatures is None:
            self.load_trackers_signatures()

        classes = self.get_embedded_classes()

        trackers = []
        for v, i in enumerate(self.signatures):
            for clazz in classes:
                tracker = self.signatures[i]
                sign = tracker['code_signature']
                if len(sign) > 1:
                    m = re.search(tracker['code_signature'], clazz)
                    if m is not None:
                        trackers.append(tracker)
                        break

        return trackers

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

    def print_apk_infos(self):
        """
        Print APK information
        """
        print("=== Information")
        print('- APK path: %s' % self.apk_path)
        print('- APK sum: %s' % self.get_sha256())
        print('- App version: %s' % self.get_version())
        print('- App version code: %s' % self.get_version_code())
        print('- App name: %s' % self.get_app_name())
        print('- App package: %s' % self.get_package())
        print('- App permissions: %s' % len(self.get_permissions()))
        for p in self.get_permissions():
            print('    - %s' % p)
        print('- App libraries: %s' % len(self.get_libraries()))
        for l in self.get_libraries():
            print('    - %s' % l)

    def print_embedded_trackers(self):
        """
        Print detected trackers
        """
        trackers = self.detect_trackers()
        print("=== Found trackers")
        for t in trackers:
            print(' - %s' % t['name'])

