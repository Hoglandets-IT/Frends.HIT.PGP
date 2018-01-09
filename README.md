- [Frends.Community.PgpDecrypt](#Frends.Community.PgpDecrypt)
   - [Installing](#installing)
   - [Building](#building)
   - [Contributing](#contributing)
   - [Documentation](#documentation)
      - [PgpDecrypt](#convertExcelFile)
		 - [Input](#input)
		 - [Options](#options)
		 - [Result](#result)
   - [License](#license)
       
# Frends.Community.PgpDecrypt
This repository contais FRENDS4 Community Task to decrypt PGP encrypted messages

## Installing
You can install the task via Frends UI Task view or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends/api/v3/index.json

## Building
Ensure that you have https://www.myget.org/F/frends/api/v3/index.json added to your nuget feeds

Clone a copy of the repo

git clone https://github.com/CommunityHiQ/Frends.Community.PgpDecrypt.git

Restore dependencies

nuget restore Frends.Community.PgpDecrypt

Rebuild the project

Run Tests with nunit3. Tests can be found under

Frends.Community.PgpDecryptTests\bin\Release\Frends.Community.PgpDecrypt.Tests.dll

Create a nuget package

`nuget pack nuspec/Frends.Community.PgpDecrypt.nuspec`

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

## Documentation

### PgpDecrypt

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
| FilePath | string  | Path to file that contains decrypted file. Note: this is same path that was given as input parameter OutputFile. Copying that path to result will enable easy references in frends, such as #result[PgpDecrypt].Filepath | `C:\temp\decrypted_file.txt`

## License
This project is licensed under the MIT License - see the LICENSE file for details
