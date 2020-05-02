import requests
import os

EXODUS_LOGIN_URI = '/api/get_auth_token/'


class ExodusConnector:
    """
    εxodus connector helps you to interact with it.
    Usage:
    >>> exodus = ExodusConnector("http://localhost:8000", "/api/report/1/")
    >>> exodus.login("user", "password")
    >>> exodus.get_report_info()
    >>> exodus.download_apk("/tmp")
    >>> exodus.upload_pcap("/tmp/my_file.pcap")
    """
    def __init__(self, host, report_info_uri):
        """
        Instantiate a new εxodus connector.
        ``report_info_uri`` is displayed on top of each report
        when you are connected with a superuser account.
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
        r = requests.post(
            '{}{}'.format(self.host, EXODUS_LOGIN_URI),
            json={'username': username, 'password': password}
        )
        ret_code = r.status_code
        if ret_code != 200:
            raise Exception('Unable to login')
        self.access_token = r.json()['token']

    def get_report_info(self):
        """
        Retrieve report information like report ID, APK download URL, ...

        {
          'report_id': 15,
          'creation_date': '2017-11-13T18:55:53.452028Z',
          'apk_dl_link': '/api/apk/15/',
          'handle':'fr.meteo',
        }

        :return: dictionary containing report information
        """
        if not self.access_token:
            raise Exception('User not authenticated')

        r = requests.get(
            '{}{}'.format(self.host, self.report_info_uri),
            headers={"Authorization": "Token {}".format(self.access_token)}
        )
        ret_code = r.status_code
        if ret_code != 200:
            raise Exception('Unable to get report info')

        self.report_info = r.json()
        return self.report_info

    def download_apk(self, destination):
        """
        Download the APK into the provided destination path.
        :param destination: path to store the downloaded APK
        :return: path of the APK e.g. /tmp/fr.meteo.apk
        """
        if not self.access_token:
            raise Exception('User not authenticated')

        if not self.report_info['apk_dl_link']:
            raise Exception('Unable to get APK download link')

        url = '{}{}'.format(self.host, self.report_info['apk_dl_link'])
        local_filename = '{}.apk'.format(self.report_info['handle'])
        local_path = os.path.join(destination, local_filename)
        r = requests.get(
            url,
            stream=True,
            headers={'Authorization': 'Token {}'.format(self.access_token)}
        )
        with open(local_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        ret_code = r.status_code
        if ret_code != 200:
            raise Exception('Unable to download the APK')
        return local_path

    def upload_pcap(self, pcap_file):
        """
        DEPRECATED
        Upload the given PCAP file. The file has be in the Wireshark PCAP format.
        Once uploaded, εxodus will automatically analyze it.
        :param pcap_file: path to the local PCAP file
        """
        url = '{}{}'.format(self.host, self.report_info['pcap_upload_link'])
        with open(pcap_file, 'rb') as f:
            r = requests.post(
                url,
                files={'file': f},
                headers={"Authorization": "Token {}".format(self.access_token), "Content-Disposition": "attachment; filename={}".format(os.path.basename(pcap_file))}
            )
            ret_code = r.status_code
            if ret_code != 200:
                raise Exception('Unable to upload the PCAP file')

    def upload_flow(self, flow_file):
        """
        DEPRECATED
        Upload the given PCAP file. The file has be in the MITMDump FLOW format.
        Once uploaded, εxodus will automatically analyze it (not implemented yet).
        :param flow_file: path to the local FLOW file
        """
        url = '{}{}'.format(self.host, self.report_info['flow_upload_link'])
        with open(flow_file, 'rb') as f:
            r = requests.post(
                url,
                files={'file': f},
                headers={"Authorization": "Token {}".format(self.access_token), "Content-Disposition": "attachment; filename={}".format(os.path.basename(flow_file))}
            )
            ret_code = r.status_code
            if ret_code != 200:
                raise Exception('Unable to upload the FLOW file')
