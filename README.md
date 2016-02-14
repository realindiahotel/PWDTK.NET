Password Toolkit (PWDTK) v2.0.0.3 for .NET 4.6.1 (And Older .NET Versions)

This API makes it easy to create crypto random salt and then hash salt+password via a HMACSHA512 implementation of PBKDF2.

The code also allows creation and enforcement of password policies via efficient regular expressions. An example of a password policy is forcing all user to use an upper case character and at least 2 numerics with a minimum length of 6 characters.

This code is very secure and no one is going to be feasibly creating rainbow tables for it anytime soon as the default salt size is 512bits (64 chars) and minimum 5000 iterations by default, just the size of the RANDOM salt alone makes rainbow tables infeasible, but in the interest of being future proof I went all out and performed key stretching as implemented in the PBKDF2 spec as well.

I have provided a very basic sample GUI which shows common usage of the API so you can see how to use it.

The package available on NuGet is made to load a compatible dll to the target project of any project created in .NET 3.5 and up. I have provided the source for those who understandably wish to build their own dll.

Feel free to review my code for security purposes and provide discussion on the discussion board if you have any issues.

I can be contacted at thashiznets@yahoo.com.au

Thanks all!

v2.0.0.3

Set target version to .NET 4.6.1.

v2.0.0.2

Merged in the GetRandomSaltHexString method provided by Hallmanac, I added a PasswordToHashHexString method to compliment the HEX salt method. A few refactors and tidying up a bit.

v2.0.0.1

In light of this article https://www.djangoproject.com/weblog/2013/sep/15/security/ I decided to put a default maximum password size of 1024 bytes so that your server doesn't cop a DOS due to big passwords taking all your resources to hash. Please ensure you catch the PasswordTooLong Exception now when hashing passwords!
Refactored code using ReSharper http://www.jetbrains.com/resharper/ and so variable/method naming should be something universal like :)
Updated the source and binary for .NET 4.5.1

v2.0.0.0

All new hashing functionality using the PBKDF2 spec as outlined here: http://www.ietf.org/rfc/rfc2898.txt
I implemented an Rfc2898 class which has PBKDF2 functionality using HMACSHA512 as the underlying Pseudo Random Function (PRF) which is better than Microsofts implementation using only HMACSHA1.
Removed key stretching via encryption as the PBKDF2 spec is performing key stretching by xor'ing multiple Hash outputs instead.
