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
#include <libguile.h>
#include "../libcrypti2c.h"

#warning GUILE EXTENSIONS NOT YET TESTED

SCM send_recv_wrapper (SCM scm_fd, SCM scm_data_to_send, SCM scm_recv_len,
                       SCM wait_time)
{

    int fd = scm_to_int (scm_fd);
    uint8_t * buf = SCM_BYTEVECTOR_CONTENTS (scm_data_to_send);
    size_t len = SCM_BYTEVECTOR_LENGTH (scm_data_to_send);
    int recv_len = scm_to_int (scm_recv_len);
    SCM scm_rsp = scm_c_make_bytevector (recv_len);
    struct timespec t = {};

    enum CI2C_STATUS_RESPONSE rsp = RSP_COMM_ERROR;

    rsp = ci2c_send_and_receive (fd, buf, len,
                                 SCM_BYTEVECTOR_CONTENTS (scm_rsp),
                                 recv_len,
                                 &t);

    return scm_cons (scm_from_int (rsp), scm_rsp);

}

SCM
j0_wrapper (SCM x)
{
    return scm_from_double (j0 (scm_to_double (x)));
}

void
acquire_bus_wrapper (SCM fd, SCM addr)
{
  ci2c_acquire_bus (scm_from_int (fd), scm_from_uint8 (addr));
}

void
init_crypti2c (void *unused)
{
    scm_c_define_gsubr ("i2c-acquire", 2, 0, 0, acquire_bus_wrapper);
    scm_c_export ("i2c-acquire", NULL);
}

void
scm_init_crypti2c_module ()
{
    scm_c_define_module ("crypti2c", init_crypti2c, NULL);
}
