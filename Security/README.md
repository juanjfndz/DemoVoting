# Security Overview Repository

The Security Repository is a collection of scripts and methods designed to ensure the security and validity of the voting process. 

The repository should  includes various implementations of identity verification methods, including digital certificates, DNI NFC, and biometric digital signatures.

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


## DNI NFC

The DNI NFC (Near Field Communication) method utilizes the Near Field Communication technology in Spanish National Identity Cards (DNI) to verify the identity of a person who is voting. The script reads the data from the NFC chip on the card and verifies the card's authenticity and identity of the user.

### Advantages of DNI NFC

The DNI NFC (Near Field Communication) method has several advantages over other identity verification methods:

1. High level of security: The NFC technology used in Spanish National Identity Cards (DNI) provides a high level of security against tampering and fraud, making it difficult for someone to fake or alter their identity.

2. Wide availability: Almost every Spanish citizen has a DNI, making this method widely available and accessible for identity verification.

3. Ease of use: The script can quickly and easily read the data from the NFC chip on the DNI, making it a fast and efficient method of identity verification.

4. Cost-effective: This method does not require any additional hardware or equipment, making it a cost-effective option for identity verification.

5. Privacy: The DNI NFC method does not require the user to share any additional personal information, ensuring their privacy is protected.

## Biometric Digital Signatures

The Biometric Digital Signatures method utilizes the user's biometric data, such as fingerprints, facial recognition, or voice recognition, to verify their identity. The script captures the biometric data of the user and compares it to the data on file to authenticate their identity.
