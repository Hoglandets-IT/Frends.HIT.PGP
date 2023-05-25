using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class ClearTextSignatureHandler
{
    private string Password { get; set; }
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string OutputFile { get; set; }
    private string Output { get; set; }
    private string PrivateKeyFile { get; set; }
    private string PrivateKey { get; set; }
    public PgpClearTextSignatureHashFunctionType HashFunction { get; set; }

    public ClearTextSignatureHandler(PgpClearTextSignatureInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        OutputFile = ModifyPathForOperatingSystem(input.OutputFile);
        Output = input.Output;
        PrivateKeyFile = ModifyPathForOperatingSystem(input.PrivateKeyFile);
        PrivateKey = input.PrivateKey;
        Password = input.Password;
        HashFunction = input.HashFunction;
    }

    private string ModifyPathForOperatingSystem(string path)
    {
        return PgpHelper.GetRightPathForOperatingSystem(path);
    }
    private Stream ConvertStringToStream(string str)
    {
        byte[] byteArray = Encoding.UTF8.GetBytes(str);
        return new MemoryStream(byteArray);
    }
    
    public Stream KeyStream()
    {
        return string.IsNullOrEmpty(PrivateKey) ? File.OpenRead(PrivateKeyFile) : PgpHelper.KeyStringStream(PrivateKey);
    }
    
    public Stream InputStream()
    {
        return string.IsNullOrEmpty(InputString) ? File.OpenRead(InputFile) : ConvertStringToStream(InputString);
    }
   
    public string GetPassword()
    {
        return Password;
    }
}