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

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stdint.h>

enum CI2C_LOG_LEVEL
  {
    SEVERE = 0,
    WARNING,
    INFO,
    DEBUG
  };

void
ci2c_set_log_level(enum CI2C_LOG_LEVEL lvl);

void
CI2C_LOG(enum CI2C_LOG_LEVEL, const char *format, ...);

void
ci2c_print_hex_string(const char *str, const uint8_t *hex, unsigned int len);

/**
 * Returns true if debug (most verbose log level) is set.
 *
 *
 * @return True if debug is enabled.
 */
bool
ci2c_is_debug (void);

#endif /* LOG_H */
