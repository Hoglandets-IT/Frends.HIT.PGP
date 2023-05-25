using System;
using System.IO;
using System.Text;

namespace Frends.HIT.Pgp.Handlers;

public class EncryptionHandler
{
    private readonly bool _isFile;
    private string InputFile { get; set; }
    private string InputString { get; set; }
    private string OutputFile { get; set; }
    private string Output { get; set; }
    private string PublicKeyFile { get; set; }
    private string PublicKey { get; set; }
    private bool UseCompression { get; set; }
    private bool SignWithPrivateKey { get; set; }
    public bool UseArmor { get; set; }
    public bool UseIntegrityCheck { get; set; }
    public PgpEncryptCompressionType CompressionType { get; set; }
    public PgpEncryptEncryptionAlgorithm EncryptionAlgorithm { get; set; }
    public PgpEncryptSigningSettings SigningSettings { get; set; }
    public string Name;
    public long Length;

    public EncryptionHandler (PgpEncryptInput input)
    {
        InputFile = ModifyPathForOperatingSystem(input.InputFile);
        InputString = input.InputString;
        OutputFile = ModifyPathForOperatingSystem(input.OutputFile);
        Output = input.Output;
        PublicKeyFile = ModifyPathForOperatingSystem(input.PublicKeyFile);
        PublicKey = input.PublicKey;
        UseArmor = input.UseArmor;
        UseIntegrityCheck = input.UseIntegrityCheck;
        UseCompression = input.UseCompression;
        CompressionType = input.CompressionType;
        EncryptionAlgorithm = input.EncryptionAlgorithm;
        SignWithPrivateKey = input.SignWithPrivateKey;
        SigningSettings = input.SigningSettings;
        _isFile = IsFile();
        SetUpInputInformation();
    }

    private bool IsFile()
    {
        return string.IsNullOrEmpty(InputString);
    }
    
    private string ModifyPathForOperatingSystem(string path)
    {
        return PgpHelper.GetRightPathForOperatingSystem(path);
    }

    private void SetUpInputInformation()
    {
        if (_isFile)
            GetFileInfo();
        else
            GetStringInfo();
    }

    private void GetStringInfo()
    {
        Name = DateTime.Now.ToString("yyyy-MM-dd");
        Length = InputString.Length;
    }
    
    private void GetFileInfo()
    {
        var file = new FileInfo(InputFile);
        if (!file.Exists)
            throw new ArgumentException("File to encrypt does not exists", InputFile);
        Name = file.Name;
        Length = file.Length;
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
    
    public Stream SigningSettingsKeyStream()
    {
        if (!string.IsNullOrEmpty(SigningSettings.PrivateKey))
        {
            return ConvertStringToStream(SigningSettings.PrivateKey);
        }
        var modifyPath = PgpHelper.GetRightPathForOperatingSystem(SigningSettings.PrivateKeyFile);
        var signingSettingsFile = new FileInfo(modifyPath);
        return signingSettingsFile.OpenRead();
    }
    
}