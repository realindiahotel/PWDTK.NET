using Microsoft.VisualStudio.TestTools.UnitTesting;
using Framework = PWDTK_DOTNET451.PWDTK;
using Standard = PWDTK_DOTNETSTANDARD.PWDTK;

namespace PWDTK.Test
{
    [TestClass]
    public class ValidateUpgradeToStandard
    {
        private readonly string pass = "testpassword123!";
        private readonly byte[] salt = Framework.GetRandomSalt();

        [TestMethod]
        public void DotNet451_CanHashAndCompare()
        {
            var hash = Framework.PasswordToHash(salt, pass);
            var areEqual = Framework.ComparePasswordToHash(salt, pass, hash);
            Assert.IsTrue(areEqual);
        }

        [TestMethod]
        public void DotNet451ToStandard_CanHashAndCompare()
        {
            var hash = Framework.PasswordToHash(salt, pass);
            var areEqual = Standard.ComparePasswordToHash(salt, pass, hash);
            Assert.IsTrue(areEqual);
        }

        [TestMethod]
        public void StandardToDotNet451_CanHashAndCompare()
        {
            var hash = Standard.PasswordToHash(salt, pass);
            var areEqual = Framework.ComparePasswordToHash(salt, pass, hash);
            Assert.IsTrue(areEqual);
        }
    }
}
