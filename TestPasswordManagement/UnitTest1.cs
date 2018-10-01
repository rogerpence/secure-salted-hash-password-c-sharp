using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace TestPasswordManagement
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestPasswordLengthsZeroTo512()
        {
            const int MAX_PASSWORD_LENGTH = 512;

            // Generate and test passwords from 0 to n characters long. 
            for (int i = 0; i < MAX_PASSWORD_LENGTH; i++)
            {
                // Generate a password of i length.
                string password = new string('a', i);
                // Get its hash (even an empty string has a hash!).
                string hash = Helpers.PasswordManagement.CreateSaltedHash(password);

                // Hash should be 88 characters long.
                //Assert.AreEqual(hash.Length, HASH_LENGTH_SHOULD_BE);
                Assert.AreEqual(hash.Length, Helpers.PasswordManagement.EXPECTED_SALTED_HASH_LENGTH);

                // The hash should authenticate. 
                bool ok = Helpers.PasswordManagement.AuthenticateUserPassword(password, hash);
                Assert.IsTrue(ok);
            }
        }

        [TestMethod]
        public void TestRandomPasswords()
        {
            const int SALT_LENGTH = 32;
            const int LOOP_TIMES = 250;

            for (int i = 0; i < LOOP_TIMES; i++) {
                // Generate a random password. 
                RNGCryptoServiceProvider passwordMaker = new RNGCryptoServiceProvider();
                byte[] passwordData = new byte[SALT_LENGTH];
                passwordMaker.GetBytes(passwordData);
                string password = Convert.ToBase64String(passwordData);

                // Get the salted hash of that password. 
                string hash = Helpers.PasswordManagement.CreateSaltedHash(password);

                // It should authenticate. 
                bool ok = Helpers.PasswordManagement.AuthenticateUserPassword(password, hash);
                Assert.IsTrue(ok);
            }
        }
    }
}
