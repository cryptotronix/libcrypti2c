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

#ifndef CRYPTI2C_GUILE_EXT_H_
#define CRYPTI2C_GUILE_EXT_H_

/**
 * Fills the BV from src and len
 *
 * @param src The source buffer
 * @param len The len, must match bv length
 * @param bv The destination bytevector
 */
void
copy_to_bytevector (const uint8_t *src, unsigned int len, SCM bv);

/**
 * Serialize the command structure and return a bytevector
 *
 * @param c The command to serialize
 *
 * @return A serialized bytevector
 */
SCM
command_to_bytevector (struct Command_ATSHA204 c);

/**
 * Builds the random command.
 *
 * @param bool_obj #t if update seed is required.
 *
 * @return A bytevector representing the built command.
 */
SCM
build_random_cmd_wrapper (SCM bool_obj);
/**
 * The main initialization function for the guile extension.
 *
 */
void
init_crypti2c (void);

#endif // EXAMPLE_H_
