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
#include "atsha204_command.h"
#include <assert.h>
#include "i2c.h"
#include "crc.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/i2c-dev.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "log.h"

SCM
open_device ()
{

  int fd;
  char *bus = "/dev/i2c-1";
  uint8_t addr = 0x42;

  if ((fd = open(bus, O_RDWR)) < 0)
    {
      CI2C_LOG (DEBUG, "%s", "Failed to open bus.");
      scm_throw (scm_from_locale_symbol ("I2C_ERROR"), NULL);
    }

  if (ioctl(fd, I2C_SLAVE, addr) < 0)
    {
      CI2C_LOG (DEBUG, "%s", "Failed set slave address.");
      scm_throw (scm_from_locale_symbol ("I2C_ERROR"), NULL);
    }

  return scm_fdopen (scm_from_int(fd),
                     scm_from_locale_string("r+b"));
}


/**
 * Fills the BV from src and len
 *
 * @param src The source buffer
 * @param len The len, must match bv length
 * @param bv The destination bytevector
 */
void
copy_to_bytevector (const uint8_t *src, unsigned int len, SCM bv)
{
  int x = 0;

  assert (SCM_BYTEVECTOR_LENGTH (bv) == len);

  for (x = 0; x < len; x++)
    {
      scm_c_bytevector_set_x (bv, x, src[x]);
    }

}

/**
 * Serialize the command structure and return a bytevector
 *
 * @param c The command to serialize
 *
 * @return A serialized bytevector
 */
SCM
command_to_bytevector (struct Command_ATSHA204 c)
{
  uint8_t c_len = 0;
  uint8_t *serialized;

  c_len = ci2c_serialize_command (&c, &serialized);

  SCM bv = scm_c_make_bytevector (c_len);

  copy_to_bytevector (serialized, c_len, bv);

  ci2c_free_wipe (serialized, c_len);

  return bv;
}

SCM
build_random_cmd_wrapper (SCM bool_obj)
{
  bool update_seed = scm_is_true (bool_obj) ? true : false;

  struct Command_ATSHA204 c = ci2c_build_random_cmd (update_seed);

  return command_to_bytevector (c);
}

void
init_crypti2c (void *unused)
{
    scm_c_define_gsubr ("ci2c-build-random", 1, 0, 0, build_random_cmd_wrapper);
    scm_c_define_gsubr ("ci2c-open-device", 0, 0, 0, open_device);

    scm_c_export ("ci2c-build-random", NULL);
    scm_c_export ("ci2c-open-device", NULL);
}
