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

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdint.h>
#include <stdbool.h>

struct ci2c_octet_buffer
{
    unsigned char *ptr; /* Pointer to buffer */
    unsigned int len;   /* Length of data */
};

/**
 * Converts an octet buffer into a printable hex string.
 *
 * @param buf The octet buffer
 *
 * @return A malloc'd character string
 */
const char*
ci2c_octet_buffer2hex_string (struct ci2c_octet_buffer buf);

/**
 * Wipes the buffer with zeroes.
 *
 * @param buf The buffer to be wiped.
 * @param len The length of the buffer
 */
void
ci2c_wipe(unsigned char *buf, unsigned int len);

/**
 * Mallocs a buffer of length len and then wipes the buffer with zeroes.
 *
 * @param len The length of the buffer to allocate
 *
 * @return The allocated buffer.  NULL on error.
 */
uint8_t*
ci2c_malloc_wipe(unsigned int len);

/* Wipes then frees the buffer */
void
ci2c_free_wipe(unsigned char* buf, unsigned int len);

/**
 * Compares two octet buffers
 *
 * @param lhs The left octet buffer
 * @param rhs The right octet buffer
 *
 * @return True if the contents are the same
 */
bool
ci2c_memcmp_octet_buffer (struct ci2c_octet_buffer lhs,
                          struct ci2c_octet_buffer rhs);

/**
 * Created a malloc'd octet buffer.
 *
 * @param len The length of the desired buffer.
 *
 * @return A malloc'd and wiped octet buffer.
 */
struct ci2c_octet_buffer
ci2c_make_buffer(unsigned int len);

/**
 * Frees and clears an octet_buffer
 *
 * @param buf The malloc'ed octet buffer
 */
void
ci2c_free_octet_buffer(struct ci2c_octet_buffer buf);

uint8_t
ci2c_reverse_bits_in_byte(uint8_t b);

/**
 * Converts an ASCII encoded Hex character string into binary.
 *
 * @param hex The null terminated ASCII Hex string
 * @param max_len The expected max len of the string
 *
 * @return The malloc'd binary encoding.  Buf.ptr will be NULL on error
 */
struct ci2c_octet_buffer
ci2c_ascii_hex_2_bin (const char* hex, unsigned int max_len);

/**
 * Returns true if the string is all hex
 *
 * @param hex The hex string to test
 * @param max_len the expected len of the string
 *
 * @return True if the string is all hex
 */
bool
ci2c_is_all_hex (const char* hex, unsigned int max_len);

/**
 * Copies the src octet buffer into the dst at the given offset.  This
 * will assert to make sure the buffer's don't overflow.
 *
 * @param dst The destination buffer.
 * @param offset The offset in the destination buffer.
 * @param src The source buffer.
 *
 * @return The updated offset (offset + dst.len)
 */

unsigned int
ci2c_copy_buffer (struct ci2c_octet_buffer dst,
                  unsigned int offset,
                  const struct ci2c_octet_buffer src);

/**
 * Copies p of length len into the octet buffer.
 *
 * @param buf The destination buffer
 * @param offset The offset in the destination buffer.
 * @param p the pointer to the data
 * @param len The lengh of the data
 *
 * @return The updated offset (offset + len)
 */
unsigned int
ci2c_copy_to_buffer (struct ci2c_octet_buffer buf,
                     unsigned int offset,
                     const uint8_t *p,
                     unsigned int len);

/**
 * XOR two buffers.  The buffers must not be zero and must be the same size.
 *
 * @param lhs The left buffer.
 * @param rhs The right buffer.
 *
 * @return A malloc'd buffer that is the XOR of the two.
 */
struct ci2c_octet_buffer
ci2c_xor_buffers (const struct ci2c_octet_buffer lhs,
                  const struct ci2c_octet_buffer rhs);

/**
 * Convert a char into a "byte".
 *
 * @param c The char to convert
 *
 * @return An unsigned int representing the char. Will return UINT_MAX
 * on error.
 */
unsigned int
ci2c_c2b (char c);
#endif /* UTIL_H */
