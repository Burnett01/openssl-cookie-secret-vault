/*
 * Copyright (C) 2016 - 2018 Steven Agyekum, s-8@posteo.mx
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

/* All of this is pseudo code though it's pretty straightforward */

int main( int argc, char **argv )
{
    /* Init all the application stuff [....] */

    /*  
    Generate CK_SECRET_MAX (20) secrets that are used
    to generate and verify cookies 
    */

    printf( "Generated %d cookie-secrets.\n", ck_secrets_generate( CK_SECRET_MAX ) );
}

/* 
SSL_CTX_set_cookie_generate_cb( ctx, cookie_generate );
*/

int cookie_generate( SSL *ssl, unsigned char *cookie, unsigned int *clen )
{
    /* Get peer information, allocate a buffer [...] */

    /* Generate the cookie with a random secret... */
    HMAC( EVP_sha256(), (const void*)ck_secrets_random(), CK_SECRET_LEN,
        (const unsigned char*)buff, bufflen, result, &reslen );
    
    /* and copy it to the provided *cookie memory location (memcpy) [...] */

    /* Clean up all the stuff [...] */

    return 1;
}

/* 
SSL_CTX_set_cookie_verify_cb( ctx, cookie_verify );
*/

int cookie_verify( SSL *ssl, unsigned char *cookie, unsigned int clen )
{
    /* Handle ssl & cookie stuff [......] */

    /* Tests whether cookie matches one of our secrets */
    if( ck_secrets_exist( buff, bufflen, cookie, clen ) == 1 )
        return 1;
    
    return 0;
}