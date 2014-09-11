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
#include "guile_ext.h"


int
ci2c_scm_open_device (const char* bus, const uint8_t addr)
{
  int fd;

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

  return fd;
}

SCM
open_device (void)
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


void
copy_to_bytevector (const uint8_t *src, unsigned int len, SCM bv)
{
  unsigned int x = 0;

  assert (SCM_BYTEVECTOR_LENGTH (bv) == len);

  for (x = 0; x < len; x++)
    {
      scm_c_bytevector_set_x (bv, x, src[x]);
    }

}

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

SCM
crc_16_wrapper (SCM bv)
{

  SCM crc_bv = scm_c_make_bytevector (sizeof (uint16_t));

  signed char* p = SCM_BYTEVECTOR_CONTENTS (bv);
  size_t len = SCM_BYTEVECTOR_LENGTH (bv);
  uint16_t crc = ci2c_calculate_crc16 (p, len);

  memcpy (SCM_BYTEVECTOR_CONTENTS (crc_bv), &crc, sizeof (uint16_t));

  return crc_bv;
}

SCM
ci2c_scm_send_and_receive (SCM to_send, SCM to_receive,
                           SCM wait_time, SCM MAX_RECV_LEN)
{

  int fd = ci2c_scm_open_device ("/dev/i2c-1", 0x60);
  struct timespec wait = {0, scm_to_long (wait_time)};

  struct ci2c_octet_buffer rsp =
    ci2c_send_and_get_rsp (fd,
                           SCM_BYTEVECTOR_CONTENTS (to_send),
                           SCM_BYTEVECTOR_LENGTH (to_send),
                           wait,
                           scm_to_int (MAX_RECV_LEN));

  close (fd);

  if (NULL == rsp.ptr)
    {
      scm_throw (scm_from_locale_symbol ("SEND-RECEIVE-ERROR"), NULL);
    }

  SCM bv = scm_c_make_bytevector (rsp.len);

  memcpy (SCM_BYTEVECTOR_CONTENTS (bv), rsp.ptr, rsp.len);

  return bv;


}

void
init_crypti2c (void)
{
    scm_c_define_gsubr ("ci2c-build-random", 1, 0, 0, build_random_cmd_wrapper);
    scm_c_define_gsubr ("ci2c-open-device", 0, 0, 0, open_device);
    scm_c_define_gsubr ("ci2c-crc16", 1, 0, 0, crc_16_wrapper);
    scm_c_define_gsubr ("ci2c-send-receive", 4, 0, 0, ci2c_scm_send_and_receive);

    scm_c_export ("ci2c-build-random", NULL);
    scm_c_export ("ci2c-open-device", NULL);
    scm_c_export ("ci2c-crc16", NULL);
    scm_c_export ("ci2c-send-receive", NULL);
}
