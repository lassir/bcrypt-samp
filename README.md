# Bcrypt for SA-MP

An implementation of bcrypt password hashing library for SA-MP written in C++.

## Benefits of bcrypt

* All passwords are automatically salted
* Bcrypt is slow, which makes offline bruteforce attacks less efficient
* The work factor can be increased as the computers become more powerful

## Functions
* `bcrypt_hash(thread_idx, thread_id, password[], cost = 12)`
* `bcrypt_check(thread_idx, thread_id, password[], hash[])`

## Callbacks
* `OnBcryptHashed(thread_idx, thread_id, const hash[])`
* `OnBcryptChecked(thread_idx, thread_id, bool:match)`

## Usage

* Add the following lines to your gamemode or filterscript:

```
native bcrypt_hash(thread_idx, thread_id, password[], cost = 12);
native bcrypt_check(thread_idx, thread_id, password[], hash[]);
 
forward OnBcryptHashed(thread_idx, thread_id, const hash[]);
forward OnBcryptChecked(thread_idx, thread_id, bool:match);
```

* Call function `bcrypt_hash` when you would like to hash user input (e.g. on registration, or when updating the work factor). Once the hash is calculated, OnBcryptHashed is called, and the parameters include the hash.

* Call function `bcrypt_check` when you would like to verify whether or not user input matches a given hash (e.g. on login). Once the verification is done, OnBcryptChecked will be called. Parameter `match` identifies whether or not the password matched the hash.

## Example
```
#include <a_samp>
 
native bcrypt_hash(thread_idx, thread_id, password[], cost = 12);
native bcrypt_check(thread_idx, thread_id, password[], hash[]);
 
forward OnBcryptHashed(thread_idx, thread_id, const hash[]);
forward OnBcryptChecked(thread_idx, thread_id, bool:match);
 
// Defining threads
enum
{
    THREAD_REGISTRATION,
    THREAD_LOGIN
};
 
// Hashing a password
bcrypt_hash(playerid, THREAD_REGISTRATION, "Hello World!", 12);
 
public OnBcryptHashed(thread_idx, thread_id, const hash[])
{
    switch(threadid)
    {
        case THREAD_REGISTRATION:
        {
            // Could return for instance $2a$12$izP1Fy.pZxOjDOCVma0UneQoQ3sUX3HxfmyibOLPcafDSL8Pj.Ety
            // The hash will be different every time even for the same input due to the random salt
 
            printf("Password hashed for %d: %s (registration)", playerid, hash);
        }
    }
    return 1;
}
 
// Checking a password
bcrypt_check(playerid, THREAD_LOGIN, inputtext, hash);
 
public OnBcryptChecked(thread_idx, thread_id, bool:match)
{
    switch(threadid)
    {
        case THREAD_LOGIN:
        {
            printf("Password checked for %d: %s (login)", playerid, (match) ? ("Correct password") : ("Incorrect password"));
        }
    }
    return 1;
}
```