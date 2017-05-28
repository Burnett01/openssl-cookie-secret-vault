# openssl-cookie-secret-vault

## Heap version

---

API:

```c
#define CK_SECRET_MAX 20
#define CK_SECRET_LEN 16

/*
Vault that contains the secrets 
*/
struct Vault
{
  unsigned char **secrets;
  size_t count;
};

/*
Creates and stores an amount of secrets
into a vault
*/
Vault *vault_init( size_t amount );

/*
Destroys a vault
*/
void vault_destroy( Vault *v );

/*
Picks a random secret off a vault
*/
unsigned char *vault_random( Vault *v );

/*
Tests whether cookie matches one of the secrets
in a vault
*/
size_t vault_sec_exists( Vault *v, unsigned char* peer, size_t plen, 
        unsigned char *cookie, size_t clen );
```

Create a vault and generate 20 secrets:

```c
Vault *v = vault_init( CK_SECRET_MAX );
```

Generate a cookie with a random secret:

```c
HMAC( EVP_sha256(), (const void*)vault_random( v ), CK_SECRET_LEN,
        (const unsigned char*)buff, bufflen, result, &reslen );
```

Test whether cookie matches one of our secrets:

```c
if( vault_sec_exists( v, buff, bufflen, cookie, clen ) == 1)
   /* Cookie is valid since we found a matching secret */
else
   /* Cookie is not valid */
```

Destroy the vault:

```c
vault_destroy( v );
```

---

Credits to Robin Seggelmann &  Michael Tuexen for their HMAC-generation snippet.
