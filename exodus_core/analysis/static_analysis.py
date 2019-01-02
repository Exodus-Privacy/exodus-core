import binascii
import hashlib
import json
import logging
import os
import re
import time
import subprocess
import tempfile
import urllib.request
import zipfile
from collections import namedtuple
from hashlib import sha256
from tempfile import NamedTemporaryFile
import itertools

from androguard.core.bytecodes import axml
from androguard.core.bytecodes.apk import APK
from cryptography.hazmat.primitives import hashes
from future.moves import sys
from gplaycli import gplaycli

PHASH_SIZE = 8


def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

class Certificate:
    def __init__(self, cert):
        self.fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1())).decode("ascii")
        self.issuer = Certificate.get_Name(cert.issuer, short = False)
        self.subject = Certificate.get_Name(cert.subject, short = False)
        self.serial = cert.serial_number

    @staticmethod
    def get_Name(name, short = False):
        """
            Return the distinguished name of an X509 Certificate

            :param name: Name object to return the DN from
            :param short: Use short form (Default: False)

            :type name: :class:`cryptography.x509.Name`
            :type short: Boolean

            :rtype: str
        """

        # For the shortform, we have a lookup table
        # See RFC4514 for more details
        sf = {
            "countryName": "C",
            "stateOrProvinceName": "ST",
            "localityName": "L",
            "organizationalUnitName": "OU",
            "organizationName": "O",
            "commonName": "CN",
            "emailAddress": "E",
        }
        return ", ".join(
            ["{}={}".format(attr.oid._name if not short or attr.oid._name not in sf else sf[attr.oid._name], attr.value)
             for
             attr in name])

    def __str__(self):
        return 'Issuer: %s \n' \
               'Subject: %s \n' \
               'Fingerprint: %s \n' \
               'Serial: %s' % (self.issuer, self.subject, self.fingerprint, self.serial)


class StaticAnalysis:
    def __init__(self, apk_path = None):
        self.apk = None
        self.apk_path = apk_path
        self.signatures = None
        self.compiled_tracker_signature = None
        self.classes = None
        self.app_details = None
        if apk_path is not None:
            self.load_apk()

    def _compile_signatures(self):
        """
        Compiles the regex associated to each signature, in order to speed up
        the trackers detection.
        :return: A compiled list of signatures.
        """
        self.compiled_tracker_signature = []
        try:
            self.compiled_tracker_signature = [re.compile(track.code_signature)
                                        for track in self.signatures]
        except TypeError:
            print("self.signatures is not iterable")

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
        self._compile_signatures()
        logging.debug('%s trackers signatures loaded' % len(self.signatures))

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

        class_regex = re.compile(r'classes.*\.dex')
        with tempfile.TemporaryDirectory() as tmp_dir:
            with zipfile.ZipFile(self.apk_path, "r") as apk_zip:
                class_infos = (info for info in apk_zip.infolist() if class_regex.search(info.filename))
                for info in class_infos:
                    apk_zip.extract(info, tmp_dir)
            dexdump = which('dexdump')
            cmd = '%s %s/classes*.dex | perl -n -e\'/[A-Z]+((?:\w+\/)+\w+)/ && print "$1\n"\'|sort|uniq' % (
                dexdump, tmp_dir)
            try:
                self.classes = subprocess.check_output(cmd, stderr = subprocess.STDOUT, shell = True,
                                                       universal_newlines = True).splitlines()
                logging.debug('%s classes found in %s' % (len(self.classes), self.apk_path))
                return self.classes
            except subprocess.CalledProcessError:
                logging.error('Unable to decode %s' % self.apk_path)
                raise Exception('Unable to decode the APK')

    def detect_trackers_in_list(self, class_list):
        """
        Detect embedded trackers in the provided classes list.
        :return: list of embedded trackers
        """
        if self.signatures is None:
            self.load_trackers_signatures()


        def _detect_tracker(sig, tracker, class_list):
            for clazz in class_list:
                if sig.search(clazz):
                    return tracker
            return None

        results = []
        args = [(self.compiled_tracker_signature[index], tracker, class_list)
                for (index, tracker) in enumerate(self.signatures) if
                     len(tracker.code_signature) > 3]

        for res in itertools.starmap(_detect_tracker, args):
            if res:
                results.append(res)

        trackers = [t for t in results if t is not None]
        logging.debug('%s trackers detected in %s' % (len(trackers), self.apk_path))
        return trackers

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
        self.load_apk()
        return self.apk.get_androidversion_name()

    def get_version_code(self):
        """
        Get the application version code
        :return: version code
        """
        self.load_apk()
        return self.apk.get_androidversion_code()

    def get_permissions(self):
        """
        Get application permissions
        :return: application permissions list
        """
        self.load_apk()
        return self.apk.get_permissions()

    def get_app_name(self):
        """
        Get application name
        :return: application name
        """
        self.load_apk()
        return self.apk.get_app_name()

    def get_package(self):
        """
        Get application package
        :return: application package
        """
        self.load_apk()
        return self.apk.get_package()

    def get_libraries(self):
        """
        Get application libraries
        :return: application libraries list
        """
        self.load_apk()
        return self.apk.get_libraries()

    def get_icon_path(self):
        """
        Get the icon path in the ZIP archive
        :return: icon path in the ZIP archive
        """
        self.load_apk()
        return self.apk.get_app_icon()

    def get_application_details(self):
        """
        Get the application details like creator, number of downloads, etc.
        :param handle: application handle
        :return: application details dictionary
        """
        self.load_apk()

        if self.app_details is not None:
            return self.app_details

        gpc = gplaycli.GPlaycli()
        gpc.token_enable = True
        gpc.token_url = "https://matlink.fr/token/email/gsfid"
        try:
            gpc.token, gpc.gsfid = gpc.retrieve_token(force_new = False)
        except (ConnectionError, ValueError):
            try:
                time.sleep(2)
                gpc.token, gpc.gsfid = gpc.retrieve_token(force_new = True)
            except (ConnectionError, ValueError) as e:
                logging.error(e)
                return None
        gpc.connect()
        objs = gpc.api.search(self.get_package(), 5)
        try:
            for obj in objs:
                if self.get_package() == obj['docId']:
                    self.app_details = obj
                    return self.app_details
            return None
        except Exception as e:
            logging.error('Unable to parse applications details')
            logging.error(e)
            return None

    def _get_icon_from_details(self, path):
        details = self.get_application_details()
        for i in details['images']:
            if i['imageType'] == 4:
                f = urllib.request.urlopen(i['url'])
                with open(path, mode = 'wb') as fp:
                    fp.write(f.read())
                    return path
        return ''

    def _get_icon_from_gplay(self, handle, path):
        """
        Download the application icon from Google Play website
        :param handle: application handle
        :param path: file to be saved
        :return: path of the saved icon
        """
        from bs4 import BeautifulSoup
        import urllib.request

        address = 'https://play.google.com/store/apps/details?id=%s' % handle
        text = urllib.request.urlopen(address).read()
        soup = BeautifulSoup(text, 'html.parser')
        i = soup.find_all('img', {'class': 'cover-image', 'alt': 'Cover art'})
        if len(i) > 0:
            url = '%s' % i[0]['src']
            if not url.startswith('http'):
                url = 'https:%s' % url
            f = urllib.request.urlopen(url)
            with open(path, mode = 'wb') as fp:
                fp.write(f.read())
                return path
        else:
            logging.error('Unable to download the icon from Google Play')
            raise FileNotFoundError('Unable to download the icon')

    @staticmethod
    def _render_drawable_to_png(self, bxml, path):
        ap = axml.AXMLPrinter(bxml)
        print(ap.get_buff())

    def save_icon(self, path):
        """
        Extract the icon from the ZIP archive and save it at the given path
        :param path: destination path of the icon
        :return: destination path of the icon, None in case of error
        """
        from PIL import Image
        icon = self.get_icon_path()
        if icon is None:
            return None

        try:
            with zipfile.ZipFile(self.apk_path) as z:
                with open(path, 'wb') as f:
                    f.write(z.read(icon))
                _ = Image.open(path)
                return path
        except:
            logging.warning('Unable to get the icon from the APK - downloading from details')
            try:
                saved_path = self._get_icon_from_details(path)
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    logging.debug('Icon downloaded from Google Play')
                    return saved_path
            except Exception as e:
                logging.error(e)
                logging.warning('Unable to get the icon from details - downloading from GPlay')
                try:
                    saved_path = self._get_icon_from_gplay(self.get_package(), path)
                    if os.path.isfile(path) and os.path.getsize(path) > 0:
                        logging.debug('Icon downloaded from Google Play')
                        return saved_path
                except Exception as e:
                    logging.error(e)
        return None

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
                logging.error('Unable to save the icon')
                return ''
            try:
                image = Image.open(ic.name).convert("RGBA")
                row, col = dhash.dhash_row_col(image, size = PHASH_SIZE)
                return row << (PHASH_SIZE * PHASH_SIZE) | col
            except IOError as e:
                logging.error(e)
                return ''

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
            parts.append(c.fingerprint.upper())
        return hashlib.sha1(' '.join(parts).encode('utf-8')).hexdigest().upper()

    def get_certificates(self):
        certificates = []
        import six
        from cryptography.x509.name import _SENTINEL, ObjectIdentifier, _NAMEOID_DEFAULT_TYPE, _ASN1Type, NameAttribute
        def _my_name_init(self, oid, value, _type = _SENTINEL):
            if not isinstance(oid, ObjectIdentifier):
                raise TypeError("oid argument must be an ObjectIdentifier instance.")
            if not isinstance(value, six.text_type):
                raise TypeError("value argument must be a text type.")
            if len(value) == 0:
                raise ValueError("Value cannot be an empty string")
            if _type == _SENTINEL:
                _type = _NAMEOID_DEFAULT_TYPE.get(oid, _ASN1Type.UTF8String)
            if not isinstance(_type, _ASN1Type):
                raise TypeError("_type must be from the _ASN1Type enum")
            self._oid = oid
            self._value = value
            self._type = _type
        NameAttribute.__init__ = _my_name_init

        signs = self.apk.get_signature_names()
        for s in signs:
            c = self.apk.get_certificate(s)
            cert = Certificate(c)
            certificates.append(cert)

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
        permissions = self.get_permissions()
        libraries = self.get_libraries()
        certificates = self.get_certificates()
        print("=== Information")
        print('- APK path: %s' % self.apk_path)
        print('- APK sum: %s' % self.get_sha256())
        print('- App version: %s' % self.get_version())
        print('- App version code: %s' % self.get_version_code())
        print('- App UID: %s' % self.get_application_universal_id())
        print('- App name: %s' % self.get_app_name())
        print('- App package: %s' % self.get_package())
        print('- App permissions: %s' % len(permissions))
        for p in permissions:
            print('    - %s' % p)
        print('- App libraries:')
        for l in libraries:
            print('    - %s' % l)
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
