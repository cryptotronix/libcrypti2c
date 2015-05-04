/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
 *
 * This file is part of EClet.
 *
 * EClet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * EClet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EClet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include <time.h>
#include "otp.h"
#include "command_util.h"
#include "configzone.h"
#include "atsha204_command.h"

struct lca_octet_buffer
lca_build_otp_zone (void)
{
    const int OTP_SIZE = 64;
    time_t tp;
    struct lca_octet_buffer result = {0,0};

    char *otp = malloc(OTP_SIZE);
    assert (otp);
    memset (otp, 0, OTP_SIZE);

    assert (time(&tp));

    assert (snprintf(otp, OTP_SIZE, "CRYPTOTRONIX SV: %s, TOL: %s",
                     PACKAGE_VERSION, ctime(&tp)));

    result.ptr = (uint8_t *)otp;
    result.len = OTP_SIZE;

    return result;
}

int
lca_burn_otp_zone (int fd, struct lca_octet_buffer otp_zone)
{
    int rc = -1;
    const unsigned int SIZE_OF_WRITE = 32;
    struct lca_octet_buffer buf;
    assert (otp_zone.ptr);
    assert (otp_zone.len == SIZE_OF_WRITE * 2);

    /* The writes must be done in 32 bytes blocks */

    /* Fill in the data */
    buf.ptr = otp_zone.ptr;
    buf.len = SIZE_OF_WRITE;

    if (lca_write32_cmd (fd, OTP_ZONE, 0, buf, NULL))
    {
        buf.ptr = otp_zone.ptr + SIZE_OF_WRITE;
        if (lca_write32_cmd (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                             buf, NULL))
        {
            rc = 0;
        }
        else
        {
            rc = -2;
        }
    }
    else
    {
        rc = -3;
    }

    return rc;
}


int
personalize (int fd, const char *config_file)
{
    assert (config_file);
    enum DEVICE_STATE state = lca_get_device_state (fd);
    struct lca_octet_buffer config, otp;
    int rc = -1;

    if (state == STATE_PERSONALIZED)
        return 0;

    if (state == STATE_FACTORY)
    {
        rc = lca_config2bin(config_file, &config);
        if (rc)

            goto OUT;

        rc = lca_burn_config_zone (fd, config);
        if (rc)
            goto FREE_CONFIG;

        rc = lca_lock_config_zone (fd, config);
        if (rc)
            goto FREE_CONFIG;

        state = lca_get_device_state(fd);

    FREE_CONFIG:
        lca_free_octet_buffer (config);
    }

    if (state == STATE_INITIALIZED)
    {
        otp = lca_build_otp_zone ();

        rc = lca_burn_otp_zone (fd, otp);

        lca_free_octet_buffer (otp);

        if (!rc)
        {
            if (lock (fd, DATA_ZONE, 0))
                rc = 0;
            else
                rc = -2;
        }

    }

OUT:
    return rc;
}
