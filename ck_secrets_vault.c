/*
 * Copyright (C) 2016 - 2017 Steven Agyekum, s-8@posteo.mx
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

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "ck_secrets_vault.h"


/*
Picks a random secret off the vault
*/
unsigned char *ck_secrets_random( void )
{
    unsigned int count = ck_secrets_count();

    return ( count > 0 ) ? ck_secrets_vault[rand() % count] : NULL;
}

/*
Returns the amount of secrets in the vault
*/
unsigned int ck_secrets_count( void )
{
    return ( sizeof( ck_secrets_vault ) / sizeof( ck_secrets_vault[0] ) );
}

/*
Creates and stores an amount of secrets
into the vault
*/
int ck_secrets_generate( unsigned int amount )
{
    int i = 0;

    do {
        if( amount <= 0 
            || amount > CK_SECRET_MAX 
            || !RAND_bytes( ck_secrets_vault[i], CK_SECRET_LENGTH ) )
            break;
        i++;
    } while( i < amount );

    return i;
}

/*
Tests whether cookie matches on of the secrets
in the vault
*/
int ck_secrets_exist( unsigned char* peer, unsigned int plen, 
            unsigned char *cookie, unsigned int clen )
{
    int i, success = 0;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int reslen = 0, count = ck_secrets_count();

    for( i = 0; i < ( !count ) ? 0 : count; i++ )
    {
        memset( &result, 0, sizeof( result ) );
        
        HMAC( EVP_sha256(), (const void*)ck_secrets_vault[i], CK_SECRET_LENGTH,
        (const unsigned char*)peer, plen, result, &reslen );

        if( clen == reslen && memcmp( result, cookie, reslen ) == 0 )
        {
            success = 1;
            break;
        }
    }

    return success;
}