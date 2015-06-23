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

#include <stdint.h>

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

#endif /* HASH_H */
