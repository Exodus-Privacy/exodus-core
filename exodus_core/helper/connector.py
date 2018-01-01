import requests
import os

EXODUS_LOGIN_URI = '/api/get_auth_token/'

class ExodusConnector:
    """
    εxodus connector helps you to interact with it.
    Usage:
    >>> exodus = Exodus("http://localhost:8000", "/api/report/1/")
    >>> exodus.login("user", "password")
    >>> exodus.get_report_infos()
    >>> exodus.download_apk("/tmp")
    >>> exodus.upload_pcap("/tmp/my_file.pcap")
    """
    def __init__(self, host, report_info_uri):
        """
        Instantiate a new εxodus connector. ``report_info_uri`` is displayed on top of each report when you are
        connected with a superuser account.
        :param host: εxodus host e.g. http://localhost:8000
        :param report_info_uri: report URI e.g. /api/report/1/
        """
        self.host = host
        self.report_info_uri = report_info_uri
        self.access_token = ''
        self.report_info = None

    def login(self, username, password):
        """
        Login with the provided credentials and retrieve an authentication token.
        :param username: username
        :param password: password
        """
        r = requests.post('%s%s' % (self.host, EXODUS_LOGIN_URI),
                json={'username':username, 'password':password})
        ret_code = r.status_code
        if ret_code != 200:
            raise ConnectionError('Unable to login')
        self.access_token = r.json()['token']

    def get_report_info(self):
        """
        Retrieve report information like APK download URL, PCAP file upload endpoint, ...

        {
          'pcap_upload_link': '/api/pcap/15/',
          'report_id': 15,
          'creation_date': '2017-11-13T18:55:53.452028Z',
          'apk_dl_link': '/api/apk/15/',
          'handle':'fr.meteo',
          'flow_upload_link': '/api/flow/15/'
        }

        :return: dictionary containing report information
        """
        r=requests.get('%s%s' % (self.host, self.report_info_uri),
            headers={"Authorization":"Token %s"%self.access_token})
        ret_code = r.status_code
        if ret_code != 200:
            raise ConnectionError('Unable to get report info')
        self.report_info = r.json()
        return self.report_info

    def download_apk(self, destination):
        """
        Download the APK into the provided destination path.
        :param destination: path to store the downloaded APK
        :return: path of the APK e.g. /tmp/fr.meteo.apk
        """
        url = '%s%s' % (self.host, self.report_info['apk_dl_link'])
        local_filename = '%s.apk' % self.report_info['handle']
        r = requests.get(url, stream=True, headers={'Authorization':'Token %s'%self.access_token})
        local_path = os.path.join(destination, local_filename)
        with open(local_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        ret_code = r.status_code
        if ret_code != 200:
            raise ConnectionError('Unable to download the APK')
        return local_path

    def upload_pcap(self, pcap_file):
        """
        Upload the given PCAP file. The file has be in the Wireshark PCAP format. Once uploaded, εxodus will
        automatically analyze it.
        :param pcap_file: path to the local PCAP file
        """
        url = '%s%s' % (self.host, self.report_info['pcap_upload_link'])
        with open(pcap_file, 'rb') as f:
            r = requests.post(url, files={'file': f},
                headers={"Authorization":"Token %s"%self.access_token, "Content-Disposition":"attachment; filename=%s"%os.path.basename(pcap_file)}
                )
            ret_code = r.status_code
            if ret_code != 200:
                raise ConnectionError('Unable to upload the PCAP file')

    def upload_flow(self, flow_file):
        """
        Upload the given PCAP file. The file has be in the MITMDump FLOW format. Once uploaded, εxodus will
        automatically analyze it (not implemented yet).
        :param flow_file: path to the local FLOW file
        """
        url = '%s%s' % (self.host, self.report_info['flow_upload_link'])
        with open(flow_file, 'rb') as f:
            r = requests.post(url, files={'file': f},
                headers={"Authorization":"Token %s"%self.access_token, "Content-Disposition":"attachment; filename=%s"%os.path.basename(flow_file)}
                )
            ret_code = r.status_code
            if ret_code != 200:
                raise ConnectionError('Unable to upload the FLOW file')
