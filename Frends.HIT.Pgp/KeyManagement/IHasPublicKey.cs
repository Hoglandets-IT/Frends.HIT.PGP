using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.HIT.Pgp
{
    public interface IHasPublicKey
    {
        /// <summary>
        /// Public key as a string
        /// </summary>
        [DefaultValue(@"")] 
        [DisplayFormat(DataFormatString = "Text")]
        string PublicKey { get; set; }
        /// <summary>
        /// Public key file path
        /// </summary>
        [DefaultValue(@"")]
        [DisplayFormat(DataFormatString = "Text")]
        string PublicKeyFile { get; set; }
    }
}