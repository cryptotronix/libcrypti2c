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

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stdint.h>

enum LCA_LOG_LEVEL
  {
    SEVERE = 0,
    WARNING,
    INFO,
    DEBUG
  };

void
lca_set_log_level(enum LCA_LOG_LEVEL lvl);

void
LCA_LOG(enum LCA_LOG_LEVEL, const char *format, ...);

void
lca_print_hex_string(const char *str, const uint8_t *hex, unsigned int len);

/**
 * Returns true if debug (most verbose log level) is set.
 *
 *
 * @return True if debug is enabled.
 */
bool
lca_is_debug (void) __attribute__ ((pure));

#endif /* LOG_H */
