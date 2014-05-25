/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of libcrypti2c.
 *
 * libcrypti2c is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * libcrypti2c is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libcrypti2c.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef HASH_H
#define HASH_H

#include <stdio.h>
#include "util.h"
#include "log.h"

/**
 * Perform a SHA256 Digest on a file stream
 *
 * @param fp The file pointer to hash
 *
 * @return A malloc'd buffer of 32 bytes containing the digest.
 * buf.ptr will be null on error
 */
struct ci2c_octet_buffer
ci2c_sha256 (FILE *fp);

/**
 * Perform a SHA 256 on a fixed data block
 *
 * @param data The data to hash
 *
 * @return The digest
 */
struct ci2c_octet_buffer
ci2c_sha256_buffer (struct ci2c_octet_buffer data);

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
ci2c_verify_hash_defaults (struct ci2c_octet_buffer challenge,
                           struct ci2c_octet_buffer challenge_rsp,
                           struct ci2c_octet_buffer key,
                           unsigned int key_slot);
#endif /* HASH_H */
