## Creating a cryptographically secure password hash 

This C# class library provides two methods: 

* `CreateSaltedHash(string clearTextPassword)` This method creates a random salt (using the .NET Framework's 
`System.Security.Cryptograpy.RNGCryptoServiceProvider` class) and then hashes that and the password (using the .NET Framework's`System.Security.Cryptograpy.Rfc2898DeriveBytes). This creates a cryptographically secure hash. 

* `AuthenticateUserPassword(string clearTextPassword, string saltedHash)` This method authenticates a clear text password by comparing it against a salted hash created with `CreateSaltedHash.`

## Software Disclaimer

The software offered in this GitHub repositiory is distributed 'as is' and with no warranties of any kind, whether express or implied, including and without limitation, any warranty of merchantability or fitness for a particular purpose.

The user (you) must assume the entire risk of using the software.

In no event shall any individual, company or organization involved in any way in the development, sale or distribution of this software be liable for any damages whatsoever relating to the use, misuse, or inability to use this software (including, without limitation, damages for loss of profits, business interruption, loss of information, or any other loss).'
