# Frends.HIT.Pgp

Frends HIT tasks for PGP operations. Tasks assumes that files have Windows style line endings (`/r/n`).

[![Unit Tests](https://github.com/Hoglandets-IT/Frends.HIT.Pgp/actions/workflows/unit.yml/badge.svg)](https://github.com/Hoglandets-IT/Frends.HIT.Pgp/actions/workflows/unit.yml) [![Build And Push](https://github.com/Hoglandets-IT/Frends.HIT.Pgp/actions/workflows/on-push-pullreq.yml/badge.svg)](https://github.com/Hoglandets-IT/Frends.HIT.Pgp/actions/workflows/on-push-pullreq.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 


# Installing

You can install the task via frends UI Task View or you can find the NuGet package from the following NuGet feed
https://www.myget.org/F/frends-community/api/v3/index.json and in Gallery view in MyGet https://www.myget.org/feed/frends-community/package/nuget/Frends.Community.Pgp

# Tasks


### PgpEncryptFile

Encrypt file with PGP.

#### Input
| Property            | Type   | Description |Example|
|---------------------|--------|-------------|-------|
| InputFile           | string | Path to file to decrypt.|`C:\temp\message.txt`|
| OutputFile          | string | Path to file that will be created. | `C:\temp\encryptedFile.pgp`|
| PublicKeyFile       | string | Path to recipients public key. | `C:\temp\publicKey.asc`|
| UseArmor            | bool   | Use ascii armor or not. |`true`|
| UseIntegrityCheck   | bool   | Check integrity of output file or not. |`true`|
| UseCompression      | bool   | Should file be compressed prior to encryption?|`true`|
| CompressionType     | enum   | Type of compression to use when encrypting.|`Zip`|
| EncryptionAlgorithm | enum   | Algorithm to use when encrypting.|`Cast5`|
| SignWithPrivateKey  | bool   | True if you want to sign the file with private key. In this case the file is first signed and then encrypted.|`false`|

#### Signing settings
Visible only if the file is to be signed

| Property               | Type   | Description |Example|
|------------------------|--------|-------------|-------|
| PrivateKeyFile         | string | Path to private key file to be used with signing.|`C:\temp\privateKeyFile.gpg`|
| PrivateKeyPassword     | string | Password to the private key.|`***`|
| SignatureHashAlgorithm | enum   | Hash algorithm to use with signature.|`Sha1`|

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains encrypted file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpEncryptFile].FilePath | `C:\temp\encryptedFile.pgp`


### PgpDecryptFile

Desrypts files that are encrypted with PGP.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to decrypt. | `C:\temp\encryptedFile.pgp`
| OutputFile  | string | Path to file that will be created. | `C:\temp\decrypted_file.txt`
| PrivateKeyFile  | string | Private key used to decrypt file. | `C:\temp\privateKey.asc`
| PassPhrase  | string | Password for private key. | 

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains decrypted file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in frends, such as #result[PgpDecryptFile].Filepath | `C:\temp\decrypted_file.txt`

### PgpSignFile

Sings text files with PGP signature.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to sign. | `C:\temp\message.txt`
| OutputFile  | string | Path to file that will be created. | `C:\temp\signed_message.txt`
| PrivateKeyFile  | string | Path to private key used to sign the file. 	 | `C:\temp\privateKey.asc`
| Password  | string |  Password for private key. | `***`
| HashFunction  | HashFunctionType | Hash function being used. | `SHA256`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains sidned file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpSignature].FilePath | `C:\temp\signed_message.txt`


### PgpVerifyFileSignature

Verifies files signed with PGP signature.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to verify. | `C:\temp\message.txt`
| OutputFolder  | string | Folder where the verified file will be created. If empty, file will be created to same folder as InputFile. | `C:\temp\ `
| PublicKeyFile  | string | Path to public key used to verify the file. 	 | `C:\temp\publicKey.asc`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to verified file. | `C:\temp\original_message.txt`
| Verified | bool  | true if verification is succesfull | false

### PgpClearTextSignFile

Sings text files with PGP clear text signature.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to decrypt. | `C:\temp\message.txt`
| OutputFile  | string | Path to file that will be created. | `C:\temp\signed_message.txt`
| PrivateKeyFile  | string | Path to private key used to sign the file. 	 | `C:\temp\privateKey.asc`
| Password  | string |  Password for private key. | `***`
| HashFunction  | string | Hash function being used. | `SHA256`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains sidned file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpClearTextSignature].FilePath | `C:\temp\signed_message.txt`

### PgpVerifyFileClearTextSignature

Verifies text files signed with PGP clear text signature.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to verify. | `C:\temp\message.txt`
| OutputFile  | string | Path to file that will be created. | `C:\temp\message_out.txt`
| PublicKeyFile  | string | Path to public key used to verify the file. 	 | `C:\temp\publicKey.asc`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to verified file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpVerifyClearTextSignature].FilePath | `C:\temp\message_out.txt`
| Verified | bool  | true if verification is succesfull | true

# Building

Clone a copy of the repo

`git clone https://github.com/CommunityHiQ/Frends.Community.Pgp.git`

Rebuild the project

`dotnet build`

Run Tests

`dotnet test`

Create a NuGet package

`dotnet pack --configuration Release`

# Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

# Change Log

| Version | Changes |
| ------- | ------- |
| 2.0.0   | First multitarget version of PGP tasks. Combines all previous tasks: [Frends.Community.PgpEncryptFile](https://github.com/CommunityHiQ/Frends.Community.PgpEncryptFile), [Frends.Community.PgpDecryptFile](https://github.com/CommunityHiQ/Frends.Community.PgpDecryptFile), [Frends.Community.PgpSignature](https://github.com/CommunityHiQ/Frends.Community.PgpSignature), [Frends.Community.PgpVerifySignature](https://github.com/CommunityHiQ/Frends.Community.PgpVerifySignature),[Frends.Community.PgpClearTextSignature](https://github.com/CommunityHiQ/Frends.Community.PgpClearTextSignature), [Frends.Community.PgpVerifyClearTextSignature](https://github.com/CommunityHiQ/Frends.Community.PgpVerifyClearTextSignature)|
| 2.0.1 | Fixed issue in DecryptFile that prevented decryption if message contained a signature list |

