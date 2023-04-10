# DemoVoting

DemoVoting is an open-source project aimed at creating a secure and efficient platform for conducting electronic voting. The project includes various components, including a certificate-based authentication system, a voting application, and a database to store the voting results.

## Certificate-based Authentication System

The certificate-based authentication system is a crucial component of the DemoVoting platform, as it allows for secure and reliable verification of voters' identities. The system utilizes PKCS#12 format (.p12 files) to verify the identity of a person who is voting, and the Common Name attribute of the certificate is hashed using the SHA-256 algorithm to obtain a unique identifier for the user.

While the certificate-based authentication system is a secure and reliable method of verifying voters' identities, we are also exploring other methods, such as DNI NFC and biometric digital signatures, to provide users with more options and increase the overall security of the system.

## Voting Application

The voting application is a user-friendly interface that allows voters to cast their votes securely and efficiently. The application includes a list of candidates, and voters can select their preferred candidate with a simple click.

To ensure the security and integrity of the voting process, the application includes various security measures, such as encryption of the voting data and secure transmission of the results to the database.

## Database

The database is a critical component of the DemoVoting platform, as it stores the voting results and allows for secure and efficient tabulation of the votes. The database is designed to be secure and reliable, with built-in redundancy and failover mechanisms to ensure that the data is always available.

## Next Steps

As a long-term project, DemoVoting has several future development plans to improve the security and functionality of the platform. Some of the planned steps include:

- Developing and implementing additional identity verification methods, such as DNI NFC and biometric digital signatures, to provide users with more options and increase the overall security of the system.
- Improving the certificate-based authentication system to include additional security measures, such as multi-factor authentication and secure storage of the certificates.
- Creating a robust and user-friendly frontend for the voting application, with additional features such as accessibility options and multi-language support.
- Further optimizing the database to improve performance and scalability, and implementing additional security measures to protect against data breaches and other threats.

It could have the next extructure:

```
voting-system/
  frontend/
    src/
      components/
        VoteForm.js
        Results.js
      App.js
      index.js
  backend/
    api/
      app.py
      database.py
    Security/
      CheckCertificate.py
```

DemoVoting is a comprehensive project, and we are committed to providing a secure, efficient, and user-friendly platform for electronic voting. We welcome contributions and feedback from the community to help us achieve these goals.
