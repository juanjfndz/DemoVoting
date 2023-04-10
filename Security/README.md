# Security

# Certificate FNMT .p12 (CheckCertification.py)

## Purpose

The purpose of this script is to handle digital certificates in PKCS#12 format (.p12 files) for verifying the identity of a person who is voting. The script loads the certificate file and verifies that it is valid and issued by the Spanish National Mint and Stamp Factory (FNMT-RCM). If the certificate is verified, the script obtains the Common Name attribute from the certificate and calculates its SHA-256 hash, which is used as a unique identifier for the user without revealing their actual identity.

## Security Considerations

The script takes several steps to ensure the security of the voting process:

1. The script verifies that the provided p12 file path is valid before loading the certificate, to prevent any unauthorized or malicious use of the script.

2. The loaded p12 file is securely erased from memory after the private key, certificate, and additional certificates have been obtained.

3. The script verifies the certificate chain of the loaded certificate to ensure that it is valid and issued by the Spanish FNMT-RCM.

4. The Common Name attribute of the certificate is hashed using the SHA-256 algorithm to obtain a unique identifier for the user without revealing their actual identity.

## Usage

To use this script, simply create an instance of the CertificateHandler class with the path to the p12 file and the password for the file:

```python
handler = CertificateHandler(p12_path='path/to/p12/file', p12_password=b'password')
```
The script will then load the certificate file, verify its validity and issuer, calculate the SHA-256 hash of the Common Name attribute, and print information about the certificate.

The hashed Common Name attribute can be accessed from the 'common_name_sha256' attribute of the CertificateHandler object:

```python
hashed_common_name = handler.common_name_sha256
```
This hashed identifier can then be used to verify that the user is a certified voter without revealing their actual identity.
