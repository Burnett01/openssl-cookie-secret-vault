# openssl-cookie-secret-vault
A simple vault for storing cookie secrets, to be used while generating and verifying a cookie during the DTLS handshake procedure (HelloVerifyRequest, RFC6347).

>The DTLS server SHOULD generate cookies in such a way that they can
>be verified without retaining any per-client state on the server.
>
>One technique is to have a randomly generated secret and generate
>cookies as:
>
>Cookie = HMAC(Secret, Client-IP, Client-Parameters)
>
>When the second ClientHello is received, the server can verify that
>the Cookie is valid and that the client can receive packets at the
>given IP address.  In order to avoid sequence number duplication in
>case of multiple cookie exchanges, the server MUST use the record
>sequence number in the ClientHello as the record sequence number in
>its initial ServerHello.  Subsequent ServerHellos will only be sent
>after the server has created state and MUST increment normally.
>
>One potential attack on this scheme is for the attacker to collect a
>number of cookies from different addresses and then reuse them to
>attack the server.  The server can defend against this attack by
>changing the Secret value frequently, thus invalidating those
>cookies.  If the server wishes that legitimate clients be able to
>handshake through the transition (e.g., they received a cookie with
>Secret 1 and then sent the second ClientHello after the server has
>changed to Secret 2)

RFC: https://tools.ietf.org/html/rfc6347

Instead of storing cookies or using the same secret over and over again, we simply generate a specific amount of secrets, store them inside a vault and randomly pick one upon cookie-creation.
Later then we match the cookie against our secrets in that vault.

---

API:
```c
#define CK_SECRET_MAX 20
#define CK_SECRET_LENGTH 16

/*
Vault that contains the secrets 
*/
unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LENGTH];

/*
Picks a random secret off the vault
*/
unsigned char *ck_secrets_random( void );

/*
Returns the amount of secrets in the vault
*/
unsigned int ck_secrets_count( void );

/*
Creates and stores an amount of secrets
into the vault
*/
int ck_secrets_generate( unsigned int amount );

/*
Tests whether cookie matches on of the secrets
in the vault
*/
int ck_secrets_exist( unsigned char* peer, unsigned int plen, 
        unsigned char *cookie, unsigned int clen );
```

Generate 20 secrets:
```c
printf( "Generated %d cookie-secrets.\n", ck_secrets_generate( 20 ) );
```


Generate a cookie with a random secret:
```c
HMAC( EVP_sha256(), (const void*)ck_secrets_random(), CK_SECRET_LENGTH,
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