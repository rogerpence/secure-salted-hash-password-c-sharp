﻿using System;
using System.Security.Cryptography;

namespace Helpers
{
    public class PasswordManagement
    {
        // The hashing function is iterative and it needs a 
        // value to indicate the number of iterations it should 
        // take. This number should be 1000+. 1152 sounded 
        // about right to me!
        const int HASH_ITERATIONS = 1152;

        // If total hash length is 64 (salt = 32 and hash = 32) 
        // then the Convert.ToBase64String length of the total 
        // salted hash is 88. If you change HASH_LENGTH or 
        // SALT_LENGTH you have to determine and change the 
        // the EXPECTED_SALTED_HASH_LENGTH.

        // EXPECTED_SALTED_HASH_LENGTH is used only in unit tests and the 
        // expected length is only significant for knowing what field 
        // length is needed for storing the string value of the 
        // salted hash in a fixed-length field. 
        public const int HASH_LENGTH = 32; 
        public const int SALT_LENGTH = 32;
        public const int EXPECTED_SALTED_HASH_LENGTH = 88;

        public static bool AuthenticateUserPassword(string clearTextPassword, string saltedHash)
        {
            // Convert salted hash to a byte stream. 
            byte[] hashBytes = Convert.FromBase64String(saltedHash.Trim());
            // First SALT_LENGTH bytes are the salt. 
            byte[] saltBytes = new byte[SALT_LENGTH];
            // Copy just the salt bytes of saltedHash into the saltBytes bytes array. 
            Array.Copy(hashBytes, 0, saltBytes, 0, SALT_LENGTH);

            // Create a new salted hash. 
            Rfc2898DeriveBytes hashMaker = new Rfc2898DeriveBytes(clearTextPassword, saltBytes);
            hashMaker.IterationCount = HASH_ITERATIONS;
            byte[] newHashBytes = hashMaker.GetBytes(HASH_LENGTH);

            // Compare its bytes starting at SALT_LENGTH to the end 
            // (which is the hashed value of the the password only)
            // to the new password hash. 

            int newHashBytesPosition = 0;
            for (int hashBytesPosition = SALT_LENGTH; 
                     hashBytesPosition < SALT_LENGTH + HASH_LENGTH; 
                     hashBytesPosition++)
            {
                if (hashBytes[hashBytesPosition] != newHashBytes[newHashBytesPosition])
                {
                    return false;
                }
                newHashBytesPosition++;
            }

            // Hash seems equal but ensure all bytes were tested. 
            return newHashBytesPosition == HASH_LENGTH;
        }

        public static string CreateSaltedHash(string clearTextPassword)
        {
            // Generate a new salt value.
            RNGCryptoServiceProvider saltMaker = new RNGCryptoServiceProvider();
            byte[] saltData = new byte[SALT_LENGTH];
            saltMaker.GetBytes(saltData);

            // Generate a new hash value of the password.
            Rfc2898DeriveBytes hashMaker = new Rfc2898DeriveBytes(clearTextPassword, saltData, HASH_ITERATIONS);
            byte[] hashData = hashMaker.GetBytes(HASH_LENGTH);
            // Join the two resulting byte streams to form the salted hash. 
            byte[] hashBytes = new byte[SALT_LENGTH + HASH_LENGTH];
            // hashBytes contains the combined bytes of the salt 
            // and the password hash. 
            // The first SALT_LENGTH bytes are the salt and the next 
            // HASH_LENGTH bytes are the password hash. The total bytes 
            // are the combined salt and password hash. 

            // | Salt     | Hash     |
            // | n bytes  | n bytes  |

            // When hashBytes is converted to a base 64 string, the 
            // resulting string is longer than SALT_LENGTH + HASH_LENGTH. 
            // In this code, SALT_LENGTH and HASH_LENGTH are boty 32 bytes 
            // and the length of the resulting string value is 88 bytes. 
            Array.Copy(saltData, 0, hashBytes, 0, SALT_LENGTH);
            Array.Copy(hashData, 0, hashBytes, SALT_LENGTH, HASH_LENGTH);

            // Return the string value of the salted hash. 
            return Convert.ToBase64String(hashBytes);
        }
    }
}
