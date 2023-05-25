using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class DecryptHandler
{
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string OutputFile { get; set; }
    private string PrivateKeyFile { get; set; }
    private string PrivateKey { get; set; }
    public string Output { get; set; }
    public string PassPhrase { get; set; }

    public DecryptHandler(PgpDecryptInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        OutputFile = ModifyPathForOperatingSystem(input.OutputFile);
        Output = input.Output;
        PrivateKeyFile = ModifyPathForOperatingSystem(input.PrivateKeyFile);
        PrivateKey = input.PrivateKey;
        PassPhrase = input.PassPhrase;
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
}