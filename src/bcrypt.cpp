#include <random>

#include "bcrypt.h"
#include "crypt_blowfish/ow-crypt.h"

#define CRYPT_OUTPUT_SIZE           (7 + 22 + 31 + 1)
#define CRYPT_GENSALT_OUTPUT_SIZE	(7 + 22 + 1)

Bcrypt::Bcrypt()
{
	this->cost = 12;
	this->prefix = "2y";
}

Bcrypt* Bcrypt::setCost(unsigned short cost)
{
	if(cost < 4)
	{
		this->cost = 4;
	}
	else if(cost > 31)
	{
		this->cost = 31;
	}
	else
	{
		this->cost = cost;
	}
	
	return this;
}

Bcrypt* Bcrypt::setPrefix(std::string prefix)
{
	if(prefix == "2a")
	{
		this->prefix = "$2a$";
	}
	else
	{
		this->prefix = "$2y$";
	}
	
	return this;
}

Bcrypt* Bcrypt::setKey(std::string key)
{
	this->key = key;	
	return this;
}

Bcrypt *Bcrypt::setHash(std::string hash)
{
	this->hash = hash;
	return this;
}

std::string Bcrypt::getHash()
{
	return this->hash;
}

void Bcrypt::generate()
{
	// Generate a random salt
	std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

	std::random_device RNG;
	std::uniform_int_distribution<int> index_distribution(0, charset.length() - 1);

	for (int i = 0; i < 22; ++i)
	{
		salt.push_back(charset.at(index_distribution(RNG)));
	}

	// Construct a settings string for use with crypt_ra
	char settings[CRYPT_GENSALT_OUTPUT_SIZE];
	crypt_gensalt_rn(this->prefix.c_str(), this->cost, salt.c_str(), salt.length(), settings, CRYPT_GENSALT_OUTPUT_SIZE);

	// Use crypt_ra to ensure thread safety
	void *data = NULL;
	int size = 0x12345678;

	std::string hash;
	this->hash = crypt_ra(this->key.c_str(), settings, &data, &size);
}

bool Bcrypt::compare()
{
	// Validate hash length
	if (this->hash.length() != 60)
		return false;

	// Use crypt_ra to ensure thread safety
	void *data = NULL;
	int size = 0x12345678;

	char *compare = new char[CRYPT_OUTPUT_SIZE];
	compare = crypt_ra(this->key.c_str(), this->hash.c_str(), &data, &size);

	if (compare == this->hash)
		return true;
	else
		return false;
}
