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

#ifndef COMMAND_ADAPTATION_H
#define COMMAND_ADAPTATION_H

#include <stdbool.h>
#include <stdint.h>
#include "../libcryptoauth.h"

/**
 * Returns a string for the enumerated response code. Useful for
 * debugging and logging functions.
 *
 * @param rsp The response code.
 *
 * @return A pointer to a static string.
 */
const char*
status_to_string (enum LCA_STATUS_RESPONSE rsp) __attribute__ ((pure));

#endif /* COMMAND_ADAPTATION_H */
