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

#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include "util.h"
#include "log.h"
#include <gcrypt.h>

/**
 * Perform a SHA256 Digest on a file stream
 *
 * @param fp The file pointer to hash
 *
 * @return A malloc'd buffer of 32 bytes containing the digest.
 * buf.ptr will be null on error
 */
struct lca_octet_buffer
lca_sha256 (FILE *fp);

/**
 * SHA256s a file and returns the gcrypt digest
 *
 * @param fp The file to hash
 * @param digest the digest to return
 *
 * @return 0 on success.
 */
int
lca_hash_file (FILE *fp, gcry_sexp_t *digest);

/**
 * Perform a SHA 256 on a fixed data block
 *
 * @param data The data to hash
 *
 * @return The digest
 */
struct lca_octet_buffer
lca_sha256_buffer (struct lca_octet_buffer data);

/**
 * Performs an offline verification of a MAC using the default settings.
 *
 * @param challenge The 32 Byte challenge
 * @param challenge_rsp The 32 Byte challenge response
 * @param key The 32 byte key
 * @param key_slot The key slot used
 *
 * @return True if matched, otherwise false
 */
bool
lca_verify_hash_defaults (struct lca_octet_buffer challenge,
                           struct lca_octet_buffer challenge_rsp,
                           struct lca_octet_buffer key,
                           unsigned int key_slot);

/**
 * Copies the src data to the destination at the offset and returns
 * an incremented offset.
 *
 * @param dst The destination buffer.
 * @param src The source buffer.
 * @param src_len The length of the src data
 * @param offset The offset in the destination, to which one should copy
 *
 * @return The updated offset
 */
unsigned int
copy_over (uint8_t *dst, const uint8_t *src, unsigned int src_len,
           unsigned int offset);

/**
 * Performs an offline verification of HMAC using the default settings.
 *
 * @param challenge The 32 Byte challenge
 * @param challenge_rsp The 32 Byte challenge response
 * @param key The 32 byte key
 * @param key_slot The key slot used
 *
 * @return True if matched, otherwise false
 */
bool
lca_verify_hmac_defaults (struct lca_octet_buffer challenge,
                           struct lca_octet_buffer challenge_rsp,
                           struct lca_octet_buffer key, unsigned int key_slot);


/**
 * Performs a software based HMAC 256 using default values for the
 * ATSHA204.
 *
 * @param challenge The 32 byte challenge to HMAC.
 * @param key The HMAC 256 key.
 * @param key_slot the key_slot to use (0-15).
 *
 * @return A buffer containing the digest
 */
struct lca_octet_buffer
lca_soft_hmac256_defaults(struct lca_octet_buffer challenge,
                          struct lca_octet_buffer key,
                          uint8_t key_slot);

#endif /* HASH_H */
