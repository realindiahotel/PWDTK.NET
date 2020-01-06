using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Framework = PWDTK_DOTNET451.PWDTK;
using Standard = PWDTK_DOTNETSTANDARD.PWDTK;

namespace PWDTK.Test
{
    [TestClass]
    public class ValidateByteArrayHexConversionChange
    {
        private readonly byte[] salt = Framework.GetRandomSalt();

        [TestMethod]
        public void DotNet451_ConversionDoesNotCorruptString()
        {
            var frameworkString = Framework.HashBytesToHexString(salt);
            var frameworkByteArray = Framework.HashHexStringToBytes(frameworkString);
            var frameworkString2 = Framework.HashBytesToHexString(frameworkByteArray);

            Assert.AreEqual(frameworkString, frameworkString2);
        }

        [TestMethod]
        public void Standard_ConversionDoesNotCorruptString()
        {
            var standardString = Standard.HashBytesToHexString(salt);
            var standardByteArray = Standard.HashHexStringToBytes(standardString);
            var standardString2 = Standard.HashBytesToHexString(standardByteArray);

            Assert.AreEqual(standardString, standardString2);
        }

        [TestMethod]
        public void DotNet451ToStandard_ConversionDoesNotCorruptString()
        {
            var frameworkString = Framework.HashBytesToHexString(salt);
            var frameworkByteArray = Framework.HashHexStringToBytes(frameworkString);
            var standardByteArray = Standard.HashHexStringToBytes(frameworkString);
            var standardStringFromFramework = Standard.HashBytesToHexString(frameworkByteArray);
            var standardStringFromStandard = Standard.HashBytesToHexString(standardByteArray);

            Assert.AreEqual(frameworkString, standardStringFromFramework);
            Assert.AreEqual(frameworkString, standardStringFromStandard);
        }

        [TestMethod]
        public void StandardToDotNet451_ConversionDoesNotCorruptString()
        {
            var standardString = Standard.HashBytesToHexString(salt);
            var standardByteArray = Standard.HashHexStringToBytes(standardString);
            var frameworkByteArray = Framework.HashHexStringToBytes(standardString);
            var frameworkStringFromFramework = Framework.HashBytesToHexString(frameworkByteArray);
            var frameworkStringFromStandard = Framework.HashBytesToHexString(standardByteArray);

            Assert.AreEqual(standardString, frameworkStringFromFramework);
            Assert.AreEqual(standardString, frameworkStringFromStandard);
        }
    }
}
