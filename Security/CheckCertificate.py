import os
from pathlib import Path
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import hashes

class CertificateHandler:
    """
    A class to handle X.509 digital certificates in PKCS#12 format (.p12 files).

    Attributes:
        _certificate (cryptography.x509.Certificate): The certificate.
        _additional_certificates (List[cryptography.x509.Certificate]): List of additional certificates in the chain.
        common_name_sha256 (str): The SHA256 hash of the common name in the certificate.

    Methods:
        __init__(self, p12_path: str, p12_password: bytes) -> None:
            Initializes the CertificateHandler object by loading the specified PKCS#12 file.
        _validate_p12_path(cls, p12_path: str) -> Optional[str]:
            Validates the specified file path.
        _load_p12_file(cls, p12_path: str, p12_password: bytes) -> Tuple[cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey, cryptography.x509.Certificate, List[cryptography.x509.Certificate]]:
            Loads the specified PKCS#12 file and returns the private key, certificate, and additional certificates in the chain.
        _verify_certificate_chain(self) -> bool:
            Verifies that the certificate chain is valid.
        _get_certificate_common_name(self) -> Optional[str]:
            Returns the common name (CN) of the certificate, if present.
        _is_certificate_issued_by_fnmt(self) -> bool:
            Returns True if the certificate was issued by the Spanish National Mint and Stamp Factory (FNMT-RCM).
        _hash_common_name(self) -> None:
            Calculates the SHA-256 hash of the certificate's common name and stores it in the 'common_name_sha256' attribute.
        _print_certificate_info(self) -> None:
            Prints information about the certificate, including its validity and common name, if present.
    """
    def __init__(self, p12_path: str, p12_password: bytes):
        """
        Initializes a CertificateHandler object with the given p12 file and password.

        Args:
            p12_path (str): The path to the p12 file.
            p12_password (bytes): The password for the p12 file.
        """
        self._certificate, self._additional_certificates = self._load_p12_file(p12_path, p12_password)
        self._hash_common_name()
        self._print_certificate_info() 

    @staticmethod
    def _validate_p12_path(p12_path: str) -> Optional[str]:
        """
        Validates that the provided p12 file path is valid.

        Args:
            p12_path (str): The path to the p12 file.

        Returns:
            Optional[str]: The absolute path to the p12 file if it exists, otherwise None.
        """
        if not p12_path:
            return None

        abs_path = os.path.abspath(p12_path)
        if os.path.isfile(abs_path):
            return abs_path
        else:
            return None

    @staticmethod
    def _load_p12_file(p12_path: str, p12_password: bytes):
        """
        Loads the private key, certificate, and additional certificates from the provided p12 file.

        Args:
            p12_path (str): The path to the p12 file.
            p12_password (bytes): The password for the p12 file.

        Raises:
            ValueError: If the provided p12 file path is invalid.

        Returns:
            Tuple: The private key, certificate, and additional certificates.
        """
        validated_path = CertificateHandler._validate_p12_path(p12_path)
        if not validated_path:
            raise ValueError("Invalid file path provided.")

        with open(validated_path, 'rb') as p12_file:
            p12_data = p12_file.read()

        private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
            p12_data, p12_password, default_backend()
        )

        # Securely erase the p12_data and private_key from memory
        p12_data = None
        private_key = None

        return certificate, additional_certificates


    def _verify_certificate_chain(self):
        """
        Verifies the certificate chain of the loaded certificate.

        Returns:
            bool: True if the certificate chain is verified, otherwise False.
        """
        verified = False

        for issuer_cert in self._additional_certificates:
            try:
                issuer_cert.public_key().verify(
                    self._certificate.signature,
                    self._certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    self._certificate.signature_hash_algorithm
                )
                verified = True
                break
            except Exception as error:
                pass

        return verified

    def _get_certificate_common_name(self) -> Optional[str]:
        """
       Retrieves the Common Name (CN) attribute from the loaded certificate.

       Returns:
           Optional[str]: The value of the Common Name attribute if it exists, otherwise None.
       """
        subject = self._certificate.subject
        common_name_attr = x509.NameOID.COMMON_NAME

        for attribute in subject:
            if attribute.oid == common_name_attr:
                return attribute.value

        return None

    def _is_certificate_issued_by_fnmt(self):
        """
        Determines if the loaded certificate was issued by the Spanish FNMT-RCM.

        Returns:
            bool: True if the certificate was issued by the Spanish FNMT-RCM, otherwise False.
        """
        issuer = self._certificate.issuer
        organization_name_attr = x509.NameOID.ORGANIZATION_NAME

        for attribute in issuer:
            if attribute.oid == organization_name_attr:
                return attribute.value == "FNMT-RCM"

        return False
    
    def _hash_common_name(self):
        """
        Hashes the Common Name attribute of the loaded certificate using SHA-256 and stores the result as a hex string.
        """
        common_name = self._get_certificate_common_name()
        if common_name is not None:
            self.common_name_sha256 = hashes.Hash(hashes.SHA256())
            self.common_name_sha256.update(common_name.encode())
            self.common_name_sha256 = self.common_name_sha256.finalize().hex()
        else:
            self.common_name_sha256 = None
    
    def _print_certificate_info(self):
        """
        Prints information about the loaded certificate, including whether it is valid and issued by FNMT and its Common Name attribute.
        """
        if self._verify_certificate_chain() and self._is_certificate_issued_by_fnmt():
            common_name = self._get_certificate_common_name()
            print(f"Certificate is valid and issued by FNMT. \nCommon Name: {common_name}")
        else:
            print("Certificate verification failed or not issued")

"""        
# Usage example

import getpass

try:
    p12_path = '/Users/juanjosefernandezmorales/Documents/FERNANDEZ_MORALES_JUAN_JOSE___45343816Y.p12'
    p12_password  = getpass.getpass("Enter your password: ").encode('utf-8')
    
    cert_handler = CertificateHandler(p12_path, p12_password)
    print(cert_handler.common_name_sha256)

# Erase the information.
finally:
    p12_path = None
    p12_password = None
    cert_handler = None
""" 
