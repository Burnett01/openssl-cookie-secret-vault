# openssl-cookie-secret-vault

A simple vault for storing cookie secrets that can be used while generating and verifying a cookie during the DTLS handshake procedure (HelloVerifyRequest, RFC6347).

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

---

### Solution / How it works

Instead of storing cookies or using the same secret over and over again, we simply generate a specific amount of secrets, store them inside a vault and randomly pick one upon cookie-creation.
Later then we match the cookie against our secrets in that vault.

---

### Source code

Two versions namely stack and heap are included.

#### Stack version: [Here](../master/stack/)

#### Heap version: [Here](../master/heap/)


