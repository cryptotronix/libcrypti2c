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

#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/**
 * Guaranteed memset function. Adapted from:
 * www.dwheeler.com/secure-programs/Secure-Programs-HOWTO/protect-secrets.html
 *
 * @param v The start of the buffer to set
 * @param c Constant byte c
 * @param n fills n bytes
 *
 * @return Returns s
 */
void *
smemset(void *s, int c, size_t n);

#endif /* UTIL_H */
