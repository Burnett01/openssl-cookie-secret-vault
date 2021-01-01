/*
 * Copyright (C) 2016 - 2021 Steven Agyekum, s-8@posteo.mx
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
static unsigned char ck_secrets_vault[CK_SECRET_MAX][CK_SECRET_LEN];

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

#ifdef __cplusplus
}
#endif

#endif /* CK_SECRETS_VAULT_H */
