using System;
using System.IO;
using System.Text;
using Frends.HIT.Pgp.PathManagement;

namespace Frends.HIT.Pgp
{
    public static class PgpKeystream
    {
        public static Stream GetPublicKeyStream(IHasPublicKey input)
        {
            if (!string.IsNullOrEmpty(input.PublicKey))
            {
                Console.WriteLine("PublicKey");
                var pgpPublicKeyBlockBytes = Encoding.UTF8.GetBytes(input.PublicKey);
                return new MemoryStream(pgpPublicKeyBlockBytes);
            }
            else if(!string.IsNullOrEmpty(input.PublicKeyFile))
            {
                Console.WriteLine("PublicKeyFile");
                try
                {
                    PgpPathManagment.GetRightPathForOperatingSystemPublicKey(input);
                    return File.OpenRead(input.PublicKeyFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error opening file: {ex.Message}");
                }
            }
            else
            {
                throw new ArgumentException($"Both PublicKey and PublicKeyFile are empty");
            }
            return null;
        }
        public static Stream GetPrivateKeyStream(IHasPrivateKey input)
        {
            if (!string.IsNullOrEmpty(input.PrivateKey))
            {
                var pgpPublicKeyBlockBytes = Encoding.UTF8.GetBytes(input.PrivateKey);
                return new MemoryStream(pgpPublicKeyBlockBytes);
            }
            else if(!string.IsNullOrEmpty(input.PrivateKeyFile))
            {
                try
                {
                    PgpPathManagment.GetRightPathForOperatingSystemPrivateKey(input);
                    return File.OpenRead(input.PrivateKeyFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error opening file: {ex.Message}");
                }
            }
            else
            {
                throw new ArgumentException($"Both PrivateKey and PrivateKeyFile are empty");
            }
            return null;
        }
    }
}