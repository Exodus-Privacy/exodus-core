from bs4 import BeautifulSoup
from collections import namedtuple
from cryptography.x509.name import _SENTINEL, ObjectIdentifier, _NAMEOID_DEFAULT_TYPE, _ASN1Type, NameAttribute
from hashlib import sha256
from PIL import Image
from tempfile import NamedTemporaryFile
import binascii
import dhash
import hashlib
import itertools
import json
import logging
import os
import re
import requests
import six
import subprocess
import tempfile
import time
import zipfile

from androguard.core.bytecodes import axml
from androguard.core.bytecodes.apk import APK
from cryptography.hazmat.primitives import hashes
from future.moves import sys
from gplaycli import gplaycli

PHASH_SIZE = 8


# TODO: move to utils.py ?
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


def get_details_from_gplaycli(handle):
    """
    Get the details from gpc like creator, number of downloads, etc
    :param handle: application handle
    :return: application details dictionary
    """
    TIME_BEFORE_RETRY = 2
    API_SEARCH_LIMIT = 5
    GPLAYCLI_TOKEN_URL = "https://matlink.fr/token/email/gsfid"

    gpc = gplaycli.GPlaycli()
    gpc.token_enable = True
    gpc.token_url = GPLAYCLI_TOKEN_URL
    try:
        gpc.token, gpc.gsfid = gpc.retrieve_token(force_new=False)
    except (Exception, SystemExit):
        try:
            time.sleep(TIME_BEFORE_RETRY)
            gpc.token, gpc.gsfid = gpc.retrieve_token(force_new=True)
        except (Exception, SystemExit) as e:
            logging.error(e)
            return None
    gpc.connect()
    gpc_results = gpc.api.search(handle, API_SEARCH_LIMIT)
    try:
        for result in gpc_results:
            if result['docId'] == handle:
                return result
        return None
    except Exception as e:
        logging.error('Unable to parse applications details')
        logging.error(e)
        return None


# class Certificate:
#     def __init__(self, cert):
#         self.fingerprint = binascii.hexlify(cert.sha1).decode("ascii")
#         self.issuer = cert.issuer.human_friendly
#         self.subject = cert.subject.human_friendly
#         self.serial = cert.serial_number
#
#     def __str__(self):
#         return 'Issuer: %s \n' \
#                'Subject: %s \n' \
#                'Fingerprint: %s \n' \
#                'Serial: %s' % (self.issuer, self.subject, self.fingerprint, self.serial)


class ExodusCoreException(Exception):
    pass


# TODO: see which elements we need to put as class attributes to avoid calling
# multiple times class functions
class StaticAnalysis:
    def __init__(self, apk_file_path: str = None):
        self.apk_file_path = apk_file_path
        # self.signatures = None
        # self.compiled_tracker_signature = None
        # self.classes = None
        # self.app_details = None
        if apk_file_path and os.path.isfile(apk_file_path):
            self.apk = APK(self.apk_file_path)
        else:
            raise ExodusCoreException("Apk file missing")
        # if apk_path is not None:

    def _compile_tracker_signatures(self):
        """
        Compiles the regex associated to each signature, in order to speed up
        the trackers detection.
        :return: A compiled list of signatures.
        """
        self.compiled_signatures = []
        # TODO: rename self.signatures (which are in fact tracker objects)
        for sign in self.signatures:
            self.compiled_signatures.append(re.compile(sign.code_signature))
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
        exodus_url = "https://reports.exodus-privacy.eu.org/api/trackers"
        r = requests.get(exodus_url)
        data = r.json()
        self.signatures = []
        for e in data['trackers']:
            self.signatures.append(namedtuple('tracker', data['trackers'][e].keys())(*data['trackers'][e].values()))
        self._compile_signatures()
        logging.debug('{} trackers signatures loaded'.format(len(self.signatures)))

    # def load_apk(self):
    #     """
    #     Load the APK file.
    #     """
    #     if self.apk:
    #         self.apk = APK(self.apk_file_path)

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
                self.classes = subprocess.check_output(
                    cmd,
                    stderr=subprocess.STDOUT,
                    shell=True,
                    universal_newlines=True
                ).splitlines()
                logging.debug('{} classes found in {}'.format(len(self.classes), self.apk_path))
                return self.classes
            except subprocess.CalledProcessError:
                logging.error('Unable to decode {}'.format(self.apk_path))
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

        # TODO: this basically does `trackers = results`
        trackers = [t for t in results if t is not None]
        logging.debug('{} trackers detected in {}'.format(len(trackers), self.apk_path))
        return trackers

    def detect_trackers(self, class_list_file=None):
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

    # def get_version(self):
    #     """
    #     Get the application version name
    #     :return: version name
    #     """
    #     self.load_apk()
    #     return self.apk.get_androidversion_name()
    #
    # def get_version_code(self):
    #     """
    #     Get the application version code
    #     :return: version code
    #     """
    #     self.load_apk()
    #     return self.apk.get_androidversion_code()

    # def get_permissions(self):
    #     """
    #     Get application permissions
    #     :return: application permissions list
    #     """
    #     self.load_apk()
    #     return self.apk.get_permissions()

    # def get_app_name(self):
    #     """
    #     Get application name
    #     :return: application name
    #     """
    #     self.load_apk()
    #     return self.apk.get_app_name()

    # def get_package(self):
    #     """
    #     Get application package
    #     :return: application package
    #     """
    #     self.load_apk()
    #     return self.apk.get_package()

    # def get_libraries(self):
    #     """
    #     Get application libraries
    #     :return: application libraries list
    #     """
    #     self.load_apk()
    #     return self.apk.get_libraries()

    # def get_icon_path(self):
    #     """
    #     Get the icon path in the ZIP archive
    #     :return: icon path in the ZIP archive
    #     """
    #     self.load_apk()
    #     return self.apk.get_app_icon()

    # def get_application_details(self):
    #     """
    #     Get the application details like creator, number of downloads, etc.
    #     :param handle: application handle
    #     :return: application details dictionary
    #     """
    #     self.load_apk()
    #
    #     if self.app_details is not None:
    #         return self.app_details
    #
    #     details = get_details_from_gplaycli(self.apk.get_package())
    #     if details is not None:
    #         self.app_details = details
    #
    #     return details

    def _get_icon_from_details(self, path):
        """
        Get icon from applications details dictionary
        :param path: path where to write the icon file
        :return: icon path
        :raises FileNotFoundError: if unable to find icon
        """
        logging.debug('Downloading icon from details')

        try:
            details = self.get_application_details()
            if details is not None:
                for i in details.get('images'):
                    if i.get('imageType') == 4:
                        f = requests.get(i.get('url'))
                        with open(path, mode='wb') as fp:
                            fp.write(f.content)
                            if os.path.isfile(path) and os.path.getsize(path) > 0:
                                logging.debug('Icon downloaded from application details')
                                return path
        except Exception as e:
            logging.warning(e)

        return ''

    def _get_icon_from_gplay(self, handle, path):
        """
        Download the application icon from Google Play website
        :param handle: application handle
        :param path: file to be saved
        :return: path of the saved icon
        :raises FileNotFoundError: if unable to download icon
        """
        logging.debug('Downloading icon from Google Play')

        try:
            address = 'https://play.google.com/store/apps/details?id={}'.format(handle)
            gplay_page_content = requests.get(address).text
            soup = BeautifulSoup(gplay_page_content, 'html.parser')
            cover_img = soup.find_all('img', {'alt': 'Cover art'})
            if len(cover_img) > 0:
                icon_url = str(cover_img[0]['src'])
                if not icon_url.startswith('http'):
                    icon_url = 'https:{}'.format(icon_url)
                f = requests.get(icon_url)
                with open(path, mode='wb') as fp:
                    fp.write(f.content)
                    if os.path.isfile(path) and os.path.getsize(path) > 0:
                        logging.debug('Icon downloaded from Google Play')
                        return path
        except Exception as e:
            logging.warning(e)
        return ''

    # @staticmethod
    # def _render_drawable_to_png(self, bxml, path):
    #     ap = axml.AXMLPrinter(bxml)
    #     print(ap.get_buff())

    def _get_icon_from_manifest(self, path) -> str:
        icon = self.apk.get_app_icon()
        if icon is None:
            raise ExodusCoreException("No icon in manifest")

        try:
            with zipfile.ZipFile(self.apk_path) as z:
                with open(path, 'wb') as f:
                    f.write(z.read(icon))
                _ = Image.open(path)
                logging.info('Get icon from APK: success')
                return path
        except Exception:
            return ''

    def _save_icon(self, path):
        """
        Extract the icon from the ZIP archive and save it at the given path
        :param path: destination path of the icon
        :return: destination path of the icon, None in case of error
        """
        try:
            saved_path = self._get_icon_from_manifest(path)
            if saved_path:
                return saved_path

            logging.warning('Unable to get the icon from the APK')
            saved_path = self._get_icon_from_details(path)
            if saved_path:
                return saved_path

            logging.warning('Unable to get the icon from the details')
            saved_path = self._get_icon_from_gplay(self.apk.get_package(), path)
            if saved_path:
                return saved_path
        except Exception:
            logging.warning("No icon found")

        raise ExodusCoreException("No icon")

    def _get_icon_phash(self):
        """
        Get the perceptual hash of the application icon
        :return: the perceptual hash, empty string in case of error
        """
        with NamedTemporaryFile() as ic:
            path = self.save_icon(ic.name)
            if path is None:
                logging.error('Unable to save the icon')
                return ''
            return self.get_phash(ic.name)

    # TODO: move to utils.py ?
    @staticmethod
    def get_phash(image_name):
        """
        Get the perceptual hash of the given image
        :param image_name: name of the image file
        :return: the perceptual hash, empty string in case of error
        """
        dhash.force_pil()

        try:
            image = Image.open(image_name).convert("RGBA")
            row, col = dhash.dhash_row_col(image, size=PHASH_SIZE)
            return row << (PHASH_SIZE * PHASH_SIZE) | col
        except IOError as e:
            logging.error(e)
            return ''

    # @staticmethod
    # def get_icon_similarity(phash_origin, phash_candidate):
    #     """
    #     Get icons similarity score [0,1.0]
    #     :param phash_origin: original icon
    #     :param phash_candidate: icon to be compared
    #     :return: similarity score [0,1.0]
    #     """
    #     diff = dhash.get_num_bits_different(phash_origin, phash_candidate)
    #     return 1 - 1. * diff / (PHASH_SIZE * PHASH_SIZE * 2)

    def _get_application_universal_id(self):
        parts = []
        parts.append(self.apk.get_package())
        for cert in self._get_certificates():
            parts.append(cert.fingerprint.upper())
        return hashlib.sha1(' '.join(parts).encode('utf-8')).hexdigest().upper()

    def _get_certificates(self):
        certificates = []
        for cert in self.apk.get_certificates():
            certificates.append({
                'issuer': cert.issuer.human_friendly,
                'subject': cert.subject.human_friendly,
                'serial': cert.serial_number,
                'fingerprint': binascii.hexlify(cert.sha1).decode("ascii"),
                # 'public_key': cert.public_key,
                # 'not_after': cert['tbs_certificate']['validity']['not_after'].native,
                # 'not_before': cert['tbs_certificate']['validity']['not_before'].native
            })
        return certificates

        # def _my_name_init(self, oid, value, _type=_SENTINEL):
        #     if not isinstance(oid, ObjectIdentifier):
        #         raise TypeError("oid argument must be an ObjectIdentifier instance.")
        #     if not isinstance(value, six.text_type):
        #         raise TypeError("value argument must be a text type.")
        #     if len(value) == 0:
        #         raise ValueError("Value cannot be an empty string")
        #     if _type == _SENTINEL:
        #         _type = _NAMEOID_DEFAULT_TYPE.get(oid, _ASN1Type.UTF8String)
        #     if not isinstance(_type, _ASN1Type):
        #         raise TypeError("_type must be from the _ASN1Type enum")
        #     self._oid = oid
        #     self._value = value
        #     self._type = _type
        # NameAttribute.__init__ = _my_name_init
        #
        # signs = self.apk.get_signature_names()
        # for s in signs:
        #     c = self.apk.get_certificate(s)
        #     cert = Certificate(c)
        #     certificates.append(cert)
        #
        # return certificates

    def _get_apk_size(self) -> int:
        """
        Get the APK file size in int
        :return: APK file size
        """
        return int(os.path.getsize(self.apk_file_path))

    def _get_apk_sha256(self) -> str:
        """
        Get the sha256sum of the APK file
        :return: hex sha256sum
        """
        BLOCKSIZE = 65536
        hasher = sha256()
        with open(self.apk_file_path, 'rb') as apk:
            buf = apk.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = apk.read(BLOCKSIZE)
        return str(hasher.hexdigest())

    # TODO: get rid of this class? (useless?)
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
        permissions = self.apk.get_permissions()
        libraries = self.apk.get_libraries()
        certificates = self._get_certificates()
        print("=== Information")
        print('- APK path: {}'.format(self.apk_path))
        print('- APK sum: {}'.format(self.get_sha256()))
        print('- App version: {}'.format(self.get_version()))
        print('- App version code: {}'.format(self.get_version_code()))
        print('- App UID: {}'.format(self._get_application_universal_id()))
        print('- App name: {}'.format(self.get_app_name()))
        print('- App package: {}'.format(self.apk.get_package()))
        print('- App permissions: {}'.format(len(permissions)))
        for perm in permissions:
            print('    - {}'.format(perm))
        print('- App libraries:')
        for lib in libraries:
            print('    - {}'.format(lib))
        print('- Certificates: {}'.format(len(certificates)))
        for cert in certificates:
            print('    - {}'.format(cert))

    def get_application_fingerprint(self) -> dict:
        """
        """
        app_fingerprint = {
            'apk_path': self.apk_file_path,
            'apk_size': self._get_apk_size(),
            'apk_sha256': self._get_apk_sha256(),
            'handle': self.apk.get_package(),
            'version_code': self.apk.get_androidversion_code(),
            'version_name': self.apk.get_androidversion_name(),
            'app_name': self.apk.get_app_name(),
            'icon_phash': self._get_icon_phash(),
            'permissions': self.apk.get_permissions(),
            'uaid': self._get_application_universal_id(),
            'certificates': self._get_certificates()
        }
        return app_fingerprint

    def print_embedded_trackers(self):
        """
        Print detected trackers
        """
        trackers = self.detect_trackers()
        print('=== Found trackers: {}'.format(len(trackers)))
        for t in trackers:
            print(' - {}'.format(t.name))


if __name__ == '__main__':
    apk_path = sys.argv[1]
    sa = StaticAnalysis(apk_path)
    sa.print_apk_infos()
    sa.print_embedded_trackers()
