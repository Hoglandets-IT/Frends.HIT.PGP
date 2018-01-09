- [Frends.Community.PgpEncrypt](#Frends.Community.PgpEncrypt)
   - [Installing](#installing)
   - [Building](#building)
   - [Contributing](#contributing)
   - [Documentation](#documentation)
      - [PgpEncrypt](#convertExcelFile)
		 - [Input](#input)
		 - [Options](#options)
		 - [Result](#result)
   - [License](#license)
       
# Frends.Community.PgpEncrypt
This repository contais FRENDS4 Community Task to decrypt PGP encrypted messages

## Installing
You can install the task via Frends UI Task view or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends/api/v3/index.json

## Building
Ensure that you have https://www.myget.org/F/frends/api/v3/index.json added to your nuget feeds

Clone a copy of the repo

git clone https://github.com/CommunityHiQ/Frends.Community.PgpEncrypt.git

Restore dependencies

nuget restore Frends.Community.PgpEncrypt

Rebuild the project

Run Tests with nunit3. Tests can be found under

Frends.Community.PgpEncryptTests\bin\Release\Frends.Community.PgpEncrypt.Tests.dll

Create a nuget package

`nuget pack nuspec/Frends.Community.PgpEncrypt.nuspec`

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

## Documentation

### PgpEncrypt

Desrypts files that are encrypted with PGP.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to decrypt. | `C:\temp\message.txt`
| OutputFile  | string | Path to file that will be created. | `C:\temp\encryptedFile.pgp`
| PublicKeyFile  | string | Path to recipients public key. | `C:\temp\publicKey.asc`
| UseArmor  | string |  Use ascii armor or not. | `true`
| UseIntegrityCheck  | string | Check integrity of output file or not. | `true`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to file that contains encrypted file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in Frends, such as #result[PgpEncrypt].FilePath | `C:\temp\encryptedFile.pgp`

## License
This project is licensed under the MIT License - see the LICENSE file for details
