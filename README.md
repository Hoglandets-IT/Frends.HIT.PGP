- [Frends.Community.PgpClearTextSignature](#Frends.Community.PgpClearTextSignature)
   - [Installing](#installing)
   - [Building](#building)
   - [Contributing](#contributing)
   - [Documentation](#documentation)
      - [PgpClearTextSignature](#convertExcelFile)
		 - [Input](#input)
		 - [Options](#options)
		 - [Result](#result)
   - [License](#license)
       
# Frends.Community.PgpVerifyClearTextSignature
This repository contais FRENDS4 Community Task to verify a PGP signature at the end of text file. 

## Installing
You can install the task via Frends UI Task view or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends/api/v3/index.json

## Building
Ensure that you have https://www.myget.org/F/frends/api/v3/index.json added to your nuget feeds

Clone a copy of the repo

git clone https://github.com/CommunityHiQ/Frends.Community.PgpVerifyClearTextSignature.git

Restore dependencies

nuget restore Frends.Community.PgpVerifyClearTextSignature

Rebuild the project

Run Tests with nunit3. Tests can be found under

Frends.Community.PgpVerifyClearTextSignatureTests\bin\Release\Frends.Community.PgpVerifyClearTextSignature.Tests.dll

Create a nuget package

`nuget pack nuspec/Frends.Community.PgpVerifyClearTextSignature.nuspec`

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

## Documentation

### PgpVerifyClearTextSignature

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

## License
This project is licensed under the MIT License - see the LICENSE file for details
