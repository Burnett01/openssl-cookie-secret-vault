# openssl-cookie-secret-vault

## Stack version

---

API:

```c
#define CK_SECRET_MAX 20
#define CK_SECRET_LEN 16

/*
Vault that contains the secrets 
*/
static unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LENGTH];

/*
Creates and stores an amount of secrets
into the vault
*/
size_t ck_secrets_generate( size_t amount );

/*
Returns the amount of secrets in the vault
*/
size_t ck_secrets_count( void );

/*
Picks a random secret off the vault
*/
unsigned char *ck_secrets_random( void );

/*
Tests whether cookie matches on of the secrets
in the vault
*/
size_t ck_secrets_exist( unsigned char* peer, size_t plen, 
        unsigned char *cookie, size_t clen );
```

Generate 20 secrets:

```c
printf( "Generated %d cookie-secrets.\n", ck_secrets_generate( CK_SECRET_MAX ) );
```


Generate a cookie with a random secret:

```c
HMAC( EVP_sha256(), (const void*)ck_secrets_random(), CK_SECRET_LEN,
        (const unsigned char*)buff, bufflen, result, &reslen );
```

Test whether cookie matches one of our secrets:

```c
if( ck_secrets_exist( buff, bufflen, cookie, clen ) == 1)
   /* Cookie is valid since we found a matching secret */
else
   /* Cookie is not valid */
```

---

Credits to Robin Seggelmann &  Michael Tuexen for their HMAC-generation snippet.
