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

#ifndef CRC_H
#define CRC_H

#include <stdbool.h>
#include <stdint.h>

#define LCA_CRC_16_LEN  2
#define LCA_POLYNOMIAL 0x8005

/**
 * Calculates a CRC16 and compares it to the specified CRC. Returns
 * true if the CRC matches.
 *
 * @param data The data on which a CRC is calculated.
 * @param data_len The length of the data.
 * @param crc A two byte CRC to which a new CRC will be compared.
 *
 * @return true if the CRC matches the calculated, otherwise false.
 */
bool lca_is_crc_16_valid (const uint8_t *data, unsigned int data_len,
                           const uint8_t *crc) __attribute__ ((pure));

/**
 * Calculates a two byte CRC over the specified data.
 *
 * @param p The pointer to the data on which a CRC will be calculated
 * @param length The length of the data.
 *
 * @return The CRC16 over the data.
 */
uint16_t lca_calculate_crc16 (const uint8_t *p, unsigned int length)
  __attribute__ ((pure));

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
