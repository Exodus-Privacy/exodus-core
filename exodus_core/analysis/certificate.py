# Partial code from https://github.com/cpu/AndroidObservatory

import re
import tempfile
from subprocess import check_output, check_call

from exodus_core.analysis.utils import stringToHex, hexToBits


class Certificate():
    def __init__(self, cert_file=None):
        self.certFile = None
        self.not_before = None
        self.not_after = None
        self.subject = None
        self.issuer = None
        self.serial = None
        self.fingerprint = None
        self.pubkey = None

        if cert_file:
            self.certFile = cert_file
            self.fromFile(cert_file)

    def __str__(self):
        return "X509 Cert. w/ Fingerprint: {0} Issuer: {1}".format(self.fingerprint, self.issuer)

    def fromFile(self, certFile):
        certInfo = check_output(["openssl", "pkcs7", "-inform", "DER",
                                 "-in", certFile, "-noout",
                                 "-print_certs", "-text"]).decode('utf-8')

        serialValParseA = re.search("^\s+Serial Number: \d+ (?:\(Negative\))?\(0x([0-9a-f:]+)\)$", certInfo,
                                    re.MULTILINE)
        serialValParseB = re.search("^\s+Serial Number:\s+(?:\(Negative\))?([0-9a-f:]+)$", certInfo, re.MULTILINE)
        issuerValParse = re.search("^\s+Issuer: (.+)$", certInfo, re.MULTILINE)
        subjectValParse = re.search("^\s+Subject: (.+)$", certInfo, re.MULTILINE)

        notBeforeValParse = re.search("^\s+Not Before: (.+)$", certInfo, re.MULTILINE)
        notAfterValParse = re.search("^\s+Not After : (.+)$", certInfo, re.MULTILINE)

        # Build X509 serial number
        if serialValParseA:
            self.serial = serialValParseA.group(1)
        elif serialValParseB:
            self.serial = stringToHex(serialValParseB.group(1))
        else:
            # e("Unable to parse X509 serial number from openssl.")
            raise Exception("Bad X509 serial number")

        # Build generic X509 information
        if issuerValParse and subjectValParse and notBeforeValParse and notAfterValParse:
            self.issuer = issuerValParse.group(1)
            self.subject = subjectValParse.group(1)
            self.not_before = notBeforeValParse.group(1)
            self.not_after = notAfterValParse.group(1)
        else:
            # e("Unable to parse generic X509 information from openssl.")
            raise Exception("Bad X509 fields")

        # Build RSA specific pubkey information
        if certInfo.find('rsaEncryption') != -1:
            pubkey = RSAKeyInfo()

            pubkeySizeValParse = re.search("^\s+(?:RSA Public Key|Public-Key): \((\d+) bit\)$", certInfo, re.MULTILINE)
            pubkeyModulusValParse = re.search("^\s+(?:Modulus|Modulus \([\d]+ bit\)):\s+([\s0-9a-f:]+)+", certInfo,
                                              re.MULTILINE)
            pubkeyExponentValParse = re.search("^\s+Exponent: (\d+) \(.*\)$", certInfo, re.MULTILINE)

            if pubkeySizeValParse and pubkeyModulusValParse and pubkeyExponentValParse:
                pubkey.bits = pubkeySizeValParse.group(1)
                pubkey.modulus = stringToHex(pubkeyModulusValParse.group(1))
                pubkey.exponent = pubkeyExponentValParse.group(1)
            else:
                # e("Unable to parse RSA Key information from openssl.")
                raise Exception("Bad RSA Key information")

        # Build DSA specific pubkey information
        elif certInfo.find('dsaEncryption') != -1:
            pubkey = DSAKeyInfo()

            pubkeyPubValParse = re.search("^\s+pub:\s+([\s0-9a-f:]+)+", certInfo, re.MULTILINE)
            pubkeyPValParse = re.search("^\s+P:\s+([\s0-9a-f:]+)+", certInfo, re.MULTILINE)
            pubkeyQValParse = re.search("^\s+Q:\s+([\s0-9a-f:]+)+", certInfo, re.MULTILINE)
            pubkeyGValParse = re.search("^\s+G:\s+([\s0-9a-f:]+)+", certInfo, re.MULTILINE)

            if pubkeyPubValParse and pubkeyPValParse and pubkeyQValParse and pubkeyGValParse:
                pubkey.p = stringToHex(pubkeyPubValParse.group(1))
                pubkey.q = stringToHex(pubkeyQValParse.group(1))
                pubkey.g = stringToHex(pubkeyGValParse.group(1))
                pubkey.pub = stringToHex(pubkeyPubValParse.group(1))

                pubkey.keybits = hexToBits(pubkey.p)
                pubkey.groupbits = hexToBits(pubkey.q)
            else:
                # e("Unable to parse DSA Key information from openssl.")
                raise Exception("Bad DSA Key information")
        else:
            # e("Unknown/Unsupported public key algorithm.")
            raise Exception("Unknown/Unsupported public key algorithm")

        self.pubkey = pubkey

        tmpFile = tempfile.NamedTemporaryFile()
        with tmpFile:
            # First extract a PEM certificate from the PKCS7 structure
            # into a temporary file (deleted at end of this with statement).
            # You can't directly access the X509 Certificate fingerprint using
            # the pkcs7 command, requiring these feats of hoop jumping.
            check_call(["openssl", "pkcs7", "-inform", "DER",
                        "-in", certFile, "-print_certs", "-out", tmpFile.name])

            # Then use the X509 command to get the fingerprint of the PEM certificate.
            certFPOutput = check_output(["openssl", "x509", "-inform", "PEM",
                                         "-in", tmpFile.name, "-noout", "-fingerprint"]).decode('utf-8')

            certFPValParse = re.search("^SHA1 Fingerprint=([0-9A-F:]+)$", certFPOutput)
            if not certFPValParse:
                # e("Unable to parse X509 certificate fingerprint")
                raise Exception("Bad X509 Certificate Fingerprint")

            self.fingerprint = stringToHex(certFPValParse.group(1))


class RSAKeyInfo():
    def __init__(self):
        self.algo = 'RSA'
        self.bits = None
        self.modulus = None
        self.exponent = None

    def __str__(self):
        return "{0} Bit RSA Pubkey".format(self.bits)


class DSAKeyInfo():
    def __init__(self):
        self.algo = 'DSA'
        self.keybits = None
        self.groupbits = None
        self.pub = None
        self.p = None
        self.q = None
        self.g = None

    def __str__(self):
        return "{0},{1} Bit DSA Pubkey".format(self.keybits, self.groupbits)
