- [Frends.Community.PgpVerifySignature](#Frends.Community.PgpVerifySignature)
   - [Installing](#installing)
   - [Building](#building)
   - [Contributing](#contributing)
   - [Documentation](#documentation)
      - [PgpVerifySignature](#convertExcelFile)
		 - [Input](#input)
		 - [Options](#options)
		 - [Result](#result)
   - [License](#license)
       
# Frends.Community.PgpVerifySignature
This repository contais FRENDS4 Community Task to verify PGP signed message. 

## Installing
You can install the task via Frends UI Task view or you can find the nuget package from the following nuget feed
https://www.myget.org/F/frends/api/v3/index.json

## Building
Ensure that you have https://www.myget.org/F/frends/api/v3/index.json added to your nuget feeds

Clone a copy of the repo

git clone https://github.com/CommunityHiQ/Frends.Community.PgpVerifySignature.git

Restore dependencies

nuget restore Frends.Community.PgpVerifySignature

Rebuild the project

Run Tests with nunit3. Tests can be found under

Frends.Community.PgpVerifySignatureTests\bin\Release\Frends.Community.PgpVerifySignature.Tests.dll

Create a nuget package

`nuget pack nuspec/Frends.Community.PgpVerifySignature.nuspec`

## Contributing
When contributing to this repository, please first discuss the change you wish to make via issue, email, or any other method with the owners of this repository before making a change.

1. Fork the repo on GitHub
2. Clone the project to your own machine
3. Commit changes to your own branch
4. Push your work back up to your fork
5. Submit a Pull request so that we can review your changes

NOTE: Be sure to merge the latest from "upstream" before making a pull request!

## Documentation

### PgpVerifySignature

Verifies files signed with PGP signature.

#### Input
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| InputFile  | string | Path to file to verify. | `C:\temp\message.txt`
| OutputFolder  | string | Folder where the verified file will be created. If empty, file will be created to same folder as InputFile. | `C:\temp\`
| PublicKeyFile  | string | Path to public key used to verify the file. 	 | `C:\temp\publicKey.asc`

#### Result
| Property  | Type  | Description |Example|
|-----------|-------|-------------|-------|
| FilePath | string  | Path to verified file. | `C:\temp\original_message.txt`
| Verified | bool  | true if verification is succesfull | false

## License
This project is licensed under the MIT License - see the LICENSE file for details
