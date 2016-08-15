/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of EClet.
 *
 * EClet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * EClet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EClet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef COMMAND_H
#define COMMAND_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include "../libcryptoauth.h"

/**
 * Read four bytes from the device.
 *
 * @param fd The open file descriptor.
 * @param zone The zone from which to read.  In some configurations,
 * four byte reads are not allowed.
 * @param addr The address from which to read.  Consult the data sheet
 * for address conversions.
 * @param buf A non-null pointer to the word to fill in.
 *
 * @return True if successful other false and buf should not be investigated.
 */
bool
read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf);



/**
 * Performs the nonce operation on the device.  Depending on the data
 * parameter, this command will either generate a new nonce or combine
 * an external value.
 *
 * @param fd The open file descriptor
 * @param data If 32 bytes, this command will load the 32 byte data
 * into the temp key register directly.  If 20 bytes, it will be
 * combined per the manual and 32 bytes of random data will be returned.
 *
 * @return If data is 32 bytes, it will return a buffer of size 1 with
 * a single 0 byte.  Otherwise, it returns a 32 byte random number.
 */
struct lca_octet_buffer
gen_nonce (int fd, struct lca_octet_buffer data);

/**
 * Generates a new nonce from the device.  This will combine the OTP
 * zone with a random number to generate the nonce.
 *
 * @param fd The open file descriptor.
 *
 * @return A 32 byte malloc'd buffer if successful.
 */
struct lca_octet_buffer
get_nonce (int fd);

/**
 * Reads 32 Bytes from the address
 *
 * @param fd The open file descriptor
 * @param zone The zone to read from
 * @param addr The address to read from
 *
 * @return 32 bytes of data or buf.ptr will be null on an error
 */
struct lca_octet_buffer
read32 (int fd, enum DATA_ZONE zone, uint8_t addr);



bool
load_nonce (int fd, struct lca_octet_buffer data);



#endif /* COMMAND_H */
