using System;
using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class VerifySignatureHandler
{
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string PublicKeyFile { get; set; }
    private string PublicKey { get; set; }
    private string OutputFolder { get; set; }
    public string Output { get; set; }
    private bool SaveFile { get; set; }
    
    public VerifySignatureHandler(PgpVerifySignatureInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        PublicKeyFile = ModifyPathForOperatingSystem(input.PublicKeyFile);
        PublicKey = input.PublicKey;
        OutputFolder = ModifyPathForOperatingSystem(input.OutputFolder);
        Output = input.Output;
        SaveFile = input.SaveFile;
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

    private string GetOutputFolderPath(string fileName)
    {
        return string.IsNullOrWhiteSpace(OutputFolder) ? Path.Combine(Path.GetDirectoryName(InputFile) ?? throw new ArgumentNullException(InputFile), fileName) : Path.Combine(OutputFolder, fileName);
    }
    
    public Stream InputStream()
    {
        return string.IsNullOrEmpty(InputString) ? File.OpenRead(InputFile) : ConvertStringToStream(InputString);
    }
    
    public Stream KeyStream()
    {
        return string.IsNullOrEmpty(PublicKey) ? File.OpenRead(PublicKeyFile) : PgpHelper.KeyStringStream(PublicKey);
    }

    public Stream OutputStream(string fileName)
    {
        if (!SaveFile) return new MemoryStream();
        var path = GetOutputFolderPath(fileName);
        return File.Create(path);
    }

    public string GetOutput()
    {
       return string.IsNullOrEmpty(Output) ? OutputFolder : Output;
    }
}