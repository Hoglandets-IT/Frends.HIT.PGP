using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class VerifyClearTextSignatureHandler
{
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string PublicKeyFile { get; set; }
    private string PublicKey { get; set; }
    private string OutputFile { get; set; }
    public string Output { get; set; }

    public VerifyClearTextSignatureHandler(PgpVerifyClearTextSignatureInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        PublicKeyFile = ModifyPathForOperatingSystem(input.PublicKeyFile);
        PublicKey = PublicKey;
        OutputFile = ModifyPathForOperatingSystem(input.OutputFile);
        Output = input.Output;
    }
    
    private string ModifyPathForOperatingSystem(string path)
    {
        return PgpHelper.GetRightPathForOperatingSystem(path);
    }
    
    private Stream ConvertStringToStream(string str)
    {
        var byteArray = Encoding.UTF8.GetBytes(str);
        return new MemoryStream(byteArray);
    }
    
    public Stream InputStream()
    {
        return string.IsNullOrEmpty(InputString) ? File.OpenRead(InputFile) : ConvertStringToStream(InputString);
    }

    public Stream KeyStream()
    {
        return string.IsNullOrEmpty(PublicKey) ? File.OpenRead(PublicKeyFile) : PgpHelper.KeyStringStream(PublicKey);
    }

    public Stream OutputStream()
    {
        return string.IsNullOrEmpty(Output) ? File.OpenRead(OutputFile) : ConvertStringToStream(Output);
    }
}