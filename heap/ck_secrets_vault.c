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

#include <assert.h>
#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "ck_secrets_vault.h"

/*
Creates and stores an amount of secrets
into the vault
*/
Vault *vault_init( size_t amount )
{
    Vault *v = malloc( sizeof( Vault ) );

    assert( v != NULL );

    v->secrets = malloc( amount * sizeof( unsigned char *) );

    assert( v->secrets != NULL );

    size_t i;

    for( i = 0; i < amount; i++ )
    {
        v->secrets[i] = calloc( (CK_SECRET_LEN + 1), sizeof( char ) );

        if( v->secrets[i] != NULL )
            RAND_bytes( v->secrets[i], CK_SECRET_LEN );
    }

    v->count = amount;

    return v;
}

/*
Destroys a vault
*/
void vault_destroy( Vault *v )
{
    assert( v != NULL );

    size_t i;

    for( i = 0; i < v->count; i++ )
    {
        if( v->secrets[i] == NULL )
            continue;

        free( v->secrets[i] );
        v->secrets[i] = NULL;
    }

    free( v->secrets );
    v->secrets = NULL;

    free( v );
    v = NULL;
}

/*
Picks a random secret off a vault
*/
unsigned char *vault_random( Vault *v )
{
    if( !v || v->count <= 0 )
        return NULL;

    size_t random = (size_t)rand();

    assert( random >= 0 );

    return v->secrets[ random % v->count ];
}

/*
Tests whether cookie matches on of the secrets
in a vault
*/
size_t vault_sec_exists( Vault *v, unsigned char* peer, size_t plen, 
        unsigned char *cookie, size_t clen )
{
    size_t i, success = 0, count = v->count;
    unsigned int reslen = 0;
    unsigned char result[EVP_MAX_MD_SIZE];

    for( i = 0; i < count; i++ )
    {
        if( v->secrets[i] == NULL )
            continue;

        memset( &result, 0, sizeof( result ) );

        HMAC( EVP_sha256(), (const void*)v->secrets[i], CK_SECRET_LEN,
            (const unsigned char*)peer, plen, result, &reslen );

        if( clen == reslen && memcmp( result, cookie, reslen ) == 0 )
        {
            success = 1;
            break;
        }
    }

    return success;
}
