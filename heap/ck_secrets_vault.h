/*
 * Copyright (C) 2016 - 2020 Steven Agyekum, s-8@posteo.mx
 * Copyright (C) 2009 - 2012 Robin Seggelmann, seggelmann@fh-muenster.de,
 *                           Michael Tuexen, tuexen@fh-muenster.de
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef CK_SECRETS_VAULT_H
#define CK_SECRETS_VAULT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CK_SECRET_MAX 20
#define CK_SECRET_LEN 16

/*
Vault that contains the secrets 
*/
typedef struct Vault Vault;

struct Vault
{
  unsigned char **secrets;
  size_t count;
};

/*
Creates and stores an amount of secrets
into the vault
*/
Vault *vault_init( size_t amount );

/*
Destroys a vault
*/
void vault_destroy( Vault *v );

/*
Picks a random secret off the vault
*/
unsigned char *vault_random( Vault *v );

/*
Tests whether cookie matches on of the secrets
in the vault
*/
size_t vault_sec_exists( Vault *v, unsigned char* peer, size_t plen, 
        unsigned char *cookie, size_t clen );

#ifdef __cplusplus
}
#endif

#endif /* CK_SECRETS_VAULT_H */
