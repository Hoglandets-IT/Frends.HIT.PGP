using System.IO;

namespace Frends.HIT.Pgp.PathManagement
{
    public static class PgpPathManagment
    {
        public static void GetRightPathForOperatingSystemPublicKey(IHasPublicKey input)
        {
            
            var newPath = Path.Combine(input.PublicKeyFile).Replace('/',
                Path.DirectorySeparatorChar);
            input.PublicKeyFile = newPath;
        }
        
        public static void GetRightPathForOperatingSystemPrivateKey(IHasPrivateKey input)
        {
            var newPath = Path.Combine(input.PrivateKeyFile).Replace('/',
                Path.DirectorySeparatorChar);
            input.PrivateKeyFile = newPath;
        }
    }
}