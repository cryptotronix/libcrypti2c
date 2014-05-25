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

#ifndef ECDSA_H
#define ECDSA_H

#include <stdio.h>
#include "util.h"
#include "log.h"


bool
ci2c_ecdsa_p256_verify (struct ci2c_octet_buffer pub_key,
                        struct ci2c_octet_buffer signature,
                        struct ci2c_octet_buffer sha256_digest);


#endif /* ECDSA_H */
