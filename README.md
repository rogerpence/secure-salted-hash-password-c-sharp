## Creating a cryptographically secure password hash 

This C# class library provides two methods: 

* `CreateSaltedHash(string clearTextPassword)` This method creates a random salt (using the .NET Framework's 
`System.Security.Cryptograpy.RNGCryptoServiceProvider` class) and then hashes that and the password (using the .NET Framework's`System.Security.Cryptograpy.Rfc2898DeriveBytes). This creates a cryptographicallyy secure hash. 

* `AuthenticateUserPassword(string clearTextPassword, string saltedHash)` This method authenticates a clear text password by comparing it against a salted hash created with `CreateSaltedHash.`