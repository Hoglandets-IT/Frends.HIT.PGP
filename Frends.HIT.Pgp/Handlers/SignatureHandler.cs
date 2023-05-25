using System;
using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class SignatureHandler
{
    private string Password { get; set; }
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string OutputFile { get; set; }
    private string Output { get; set; }
    private string PrivateKeyFile { get; set; }
    private string PrivateKey { get; set; }
    public PgpSignatureHashFunctionType HashFunction { get; set; }
    public string Name;
    public long Length;

    public SignatureHandler(PgpSignatureInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        OutputFile = ModifyPathForOperatingSystem(input.OutputFile);
        Output = input.Output;
        PrivateKeyFile = ModifyPathForOperatingSystem(input.PrivateKeyFile);
        PrivateKey = input.PrivateKey;
        HashFunction = input.HashFunction;
        Password = input.Password;
        SetUpInputInformation();
    }
    
    private string ModifyPathForOperatingSystem(string path)
    {
        return PgpHelper.GetRightPathForOperatingSystem(path);
    }
    
    private void SetUpInputInformation()
    {
        if (string.IsNullOrEmpty(InputString))
            GetFileInfo();
        else
            GetStringInfo();
    }

    private void GetStringInfo()
    {
        Name = DateTime.Now.ToString("yyyy-MM-dd");
        Length = InputString.Length;
    }
    
    private Stream ConvertStringToStream(string str)
    {
        byte[] byteArray = Encoding.UTF8.GetBytes(str);
        return new MemoryStream(byteArray);
    }
    
    private void GetFileInfo()
    {
        var file = new FileInfo(InputFile);
        if (!file.Exists)
            throw new ArgumentException("File to encrypt does not exists", InputFile);
        Name = file.Name;
        Length = file.Length;
    }
    
    public Stream KeyStream()
    {
        return string.IsNullOrEmpty(PrivateKey) ? File.OpenRead(PrivateKeyFile) : PgpHelper.KeyStringStream(PrivateKey);
    }

    public string GetPassword()
    {
        return Password;
    }
    
    public Stream InputStream()
    {
        return string.IsNullOrEmpty(InputString) ? File.OpenRead(InputFile) : ConvertStringToStream(InputString);
    }
    
}