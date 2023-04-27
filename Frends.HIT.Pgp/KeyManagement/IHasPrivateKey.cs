using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.HIT.Pgp
{
    public interface IHasPrivateKey
    {
        /// <summary>
        /// Private key as a string
        /// </summary>
        [DefaultValue(@"")]
        [DisplayFormat(DataFormatString = "Text")]
        string PrivateKey { get; set; }
        /// <summary>
        /// Private key file path
        /// </summary>
        [DefaultValue(@"")]
        [DisplayFormat(DataFormatString = "Text")]
        string PrivateKeyFile { get; set; }
    }
}