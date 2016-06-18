/*
 * Copyright (C)      - 2016 Steven Agyekum, s-8@posteo.mx
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

#include "ck_secrets_vault.h"


int ck_secrets_generate(int amount) {
    int i = 0;

    do {
        if(amount <= 0 
            || amount > CK_SECRET_MAX 
            || !RAND_bytes(ck_secrets_vault[i], CK_SECRET_LENGTH))
            break;
        i++;
    } while(i < amount);

    return i;
}

int ck_secrets_count() {
    return sizeof(ck_secrets_vault)/sizeof(ck_secrets_vault[0]);
}

unsigned char *ck_secrets_random() {
    return (ck_secrets_count() > 0) ? ck_secrets_vault[rand() % ck_secrets_count()] : NULL;
}

int ck_secrets_exist(unsigned char* peer, unsigned int peer_len, unsigned char *cookie, unsigned int cookie_len) {
    int i, success = 0;

    for(i = 0; i < ck_secrets_count(); i++) {

        unsigned char result[EVP_MAX_MD_SIZE];
        unsigned int result_len;
        
        HMAC(EVP_sha256(), (const void*) ck_secrets_vault[i], CK_SECRET_LENGTH,
        (const unsigned char*) peer, peer_len, result, &result_len);

        if (cookie_len == result_len && memcmp(result, cookie, result_len) == 0)
            goto found;
        
    }
    
    found:
        success = 1;
    
    OPENSSL_free(peer);
    return success;
}