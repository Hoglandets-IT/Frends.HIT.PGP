- [Frends.Community.PgpEncryptFile](#Frends.Community.PgpEncryptFile)
   - [Documentation](#documentation)
      - [PgpEncryptFile](#convertExcelFile)
		 - [Input](#input)
		 - [Options](#options)
		 - [Result](#result)
   - [Installing](#installing)
   - [Building](#building)
   - [Contributing](#contributing)
   - [License](#license)
       
# Frends.Community.PgpEncryptFile
This repository contais FRENDS4 Community Task to decrypt PGP encrypted messages

## Documentation

### PgpEncryptFile

Desrypts files that are encrypted with PGP.

#### Input
| Property            | Type   | Description |Example|
|---------------------|--------|-------------|-------|
| InputFile           | string | Path to file to decrypt.|`C:\temp\message.txt`|
| OutputFile          | string | Path to file that will be created. | `C:\temp\encryptedFile.pgp`|
| PublicKeyFile       | string | Path to recipients public key. | `C:\temp\publicKey.asc`|
| EncryptionAlgorithm | enum   | Algorithm to use when encrypting|`Cast5`|
| CompressionType     | enum   | Type of compression to use when encrypting|`Zip`|
| UseArmor            | string | Use ascii armor or not. |`true`|
| UseIntegrityCheck   | string | Check integrity of output file or not. |`true`|
| SignWithPrivateKey  | bool   | True if you want to sign the file with private key. In this case the file is first signed and then encrypted|`false`|

#### Signing settings
Visible only if the file is to be signed

| Property               | Type   | Description |Example|
|------------------------|--------|-------------|-------|
| PrivateKeyFile         | string | Path to private key file to be used with signing|`C:\temp\privateKeyFile.gpg`|
| PrivateKeyPassword     | string | Password to the private key|`***`|
| SignatureHashAlgorithm | enum   | Hash algorithm to use with signature|`Sha1`|

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains encrypted file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpEncryptFile].FilePath | `C:\temp\encryptedFile.pgp`

## Installing
You can install the task via Frends UI Task view or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends/api/v3/index.json

## Building

Clone a copy of the repo

```sh
git clone https://github.com/CommunityHiQ/Frends.Community.PgpEncryptFile.git
```
Restore dependencies

```sh
nuget restore Frends.Community.PgpEncryptFile
```
Rebuild the project with Release configuration

Run Tests with nunit3. Tests can be found under

Frends.Community.PgpEncryptFileTests\bin\Release\Frends.Community.PgpEncryptFile.Tests.dll

Create a nuget package
```sh
nuget pack nuspec/Frends.Community.PgpEncryptFile.nuspec -properties Configuration=Release
```

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

## License
This project is licensed under the MIT License - see the LICENSE file for details
