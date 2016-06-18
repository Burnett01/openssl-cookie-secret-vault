# openssl-cookie-secret-vault
This is a simple vault for cookie-secrets that can be used in DTLS handshake procedure (HelloVerifyRequest) as described in RFC6347

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

---

API:
```c
//Maximum amount of secrets our vault can hold
#define CK_SECRET_MAX 20

//Length of a secret
#define CK_SECRET_LENGTH 16

//Storage of secrets
unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LENGTH]; 

 //Pick a random secret
unsigned char *ck_secrets_random();

//Generate an amount of secrets
int ck_secrets_generate(int amount); 

//Count secrets inside vault
int ck_secrets_count();

//Check whether secret for a cookie exist (matches)
int ck_secrets_exist(unsigned char* peer, unsigned int peer_len, unsigned char *cookie, unsigned int cookie_len);
```

Generate 20 secrets:
```c
printf("Generated %d cookie-secrets.\n", ck_secrets_generate(20));
```


Generate a cookie with a random secret:
```c
HMAC(EVP_sha256(), (const void*) ck_secrets_random(), CK_SECRET_LENGTH,
        (const unsigned char*) buffer, length, result, &resultlength);
```

Test whether cookie matches one of our secrets:
```c
if(ck_secrets_exist(buffer, length, cookie, cookie_len) == 1)
   //exists
else
   //negative
```


Credits to Robin Seggelmann &  Michael Tuexen for their HMAC-generation snippet.