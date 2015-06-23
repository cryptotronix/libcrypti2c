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

#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

#define LCA_CRC_16_LEN  2
#define LCA_POLYNOMIAL 0x8005

/* CRC Helper routines */
uint16_t
update_crc16_normal(const uint16_t table[], uint16_t crc, char c )
  __attribute__ ((pure));

uint16_t
update_crc16_reflected(const uint16_t table[], uint16_t crc, char c )
  __attribute__ ((pure));

uint16_t
update_crc16_8005( uint16_t crc, char c )
  __attribute__ ((pure));

#endif /* CRC_H */
