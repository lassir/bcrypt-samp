# Bcrypt for SA-MP

An implementation of bcrypt password hashing library for Pawn written in C++.

## Benefits of bcrypt

* All passwords are automatically salted
* Bcrypt is slow, which makes offline bruteforce attacks less efficient
* The work factor can be increased as the computers become more powerful

## Functions
* `bcrypt_hash(key[], cost = 12, callback_name[], callback_format[] = "", {Float, _}:...);`
* `bcrypt_get_hash(dest[]);`
* `bcrypt_check(key[], hash[], callback_name[], callback_format[] = "", {Float, _}:...);`
* `bool:bcrypt_is_equal();`
* `bcrypt_set_thread_limit(value);`

## Usage

* Copy the plugin file and the include file to their appropriate directories

* Include the .inc file in your gamemode or filterscript (#include <bcrypt>)

* Call function `bcrypt_hash` when you would like to hash user input (e.g. on registration, or when updating the work factor). Once the hash is calculated, the callback set in the parameters will be called, and the hash can be acquired using `bcrypt_get_hash` function

* Call function `bcrypt_check` when you would like to verify whether or not user input matches a given hash (e.g. on login). Once the verification is done, the callback set in the parameters will be called, and the result can be acquired using `bcrypt_is_equal` fcuntion

* If you would like to override the default number of threads used, you may use function `bcrypt_set_thread_limit`. In most cases, however, the default value is adequate.

## Example
```
#include <a_samp>
#include <bcrypt>

#define BCRYPT_COST 12

forward OnPasswordHashed(playerid);
forward OnPasswordChecked(playerid);
 
public OnDialogResponse(playerid, dialogid, response, listitem, inputtext[])
{
    switch(dialogid)
    {
        case DIALOG_REGISTRATION:
        {
			bcrypt_hash(inputtext, BCRYPT_COST, "OnPasswordHashed", "d", playerid);
        }

        case DIALOG_LOGIN:
        {
            // Variable hash is expected to contain the hash loaded from the database
            bcrypt_check(playerid, BCRYPT_LOGIN, inputtext, hash);
        }
    }

    return 1;
}

public OnPasswordHashed(playerid)
{
	new hash[BCRYPT_HASH_LENGTH];
	bcrypt_get_hash(hash);
	
	printf("Password hashed for player %d: %s", playerid, hash);
	return 1;
}

public OnPasswordChecked(playerid)
{
	new bool:match = bcrypt_is_equal();
	
	printf("Password checked for %d: %s", (match) ? ("Match") : ("No match"));
	return 1;
}
```