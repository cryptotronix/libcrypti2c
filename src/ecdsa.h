/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of libcryptoauth.
 *
 * libcryptoauth is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcryptoauth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libcryptoauth.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef ECDSA_H
#define ECDSA_H

#include <stdio.h>
#include <gcrypt.h>
#include "util.h"
#include "log.h"


bool
lca_ecdsa_p256_verify (struct lca_octet_buffer pub_key,
                        struct lca_octet_buffer signature,
                        struct lca_octet_buffer sha256_digest);

/**
 * Adds the uncompressed point format tag (0x04) to the Public Key
 *
 * @param q The 64 byte P-256 public key
 *
 * @return A new malloc'd buffer with 65 bytes, starting with
 * 0x04. The original buffer will be free'd
 */
struct lca_octet_buffer
lca_add_uncompressed_point_tag (struct lca_octet_buffer q);

/**
 * Prints out the sexp to the logging facility.
 *
 * @param to_print The sexp to print.
 */
void
lca_print_sexp (gcry_sexp_t to_print);

/**
 * Creates an ECDSA P256 Key pair in software.
 *
 * @param key Pointer to key storage
 *
 * @return libgcrypt result code
 */
int
lca_gen_soft_keypair (gcry_sexp_t *key);

int
lca_soft_sign (gcry_sexp_t *key_pair, struct lca_octet_buffer hash,
               gcry_sexp_t  *sig_out);

/**
 * Load an ECDSA private key from a file.
 *
 * @param keyfile The file to load.
 * @param key The gcrypt key struct to fill in
 *
 * @return 0 on success
 */
int
lca_load_signing_key (const char *keyfile, gcry_sexp_t *key);

int
lca_ssig2buffer (const gcry_sexp_t *sig, struct lca_octet_buffer *r_out,
                 struct lca_octet_buffer *s_out);

struct lca_octet_buffer
lca_sig2buf (const gcry_sexp_t *sig);

#endif /* ECDSA_H */
