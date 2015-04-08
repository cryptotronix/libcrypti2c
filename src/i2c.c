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

#include "i2c.h"
#include "crc.h"
#include <assert.h>
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

int
lca_setup(const char* bus)
{
  assert(NULL != bus);

  int fd;

  if ((fd = open(bus, O_RDWR)) < 0)
    {
      perror("Failed to open I2C bus\n");
      exit(1);
    }

  return fd;

}

void
lca_acquire_bus(int fd, int addr)
{
  if (ioctl(fd, I2C_SLAVE, addr) < 0)
    {
      perror("Failed to acquire bus access and/or talk to slave.\n");

      exit(1);
  }

}



bool
lca_wakeup(int fd)
{

  uint8_t wup[] = {0, 0};
  unsigned char buf[4] = {0};
  bool awake = false;

  /* The assumption here that the fd is the i2c fd.  Of course, it may
   * not be, so this may loop for a while (read forever).  This should
   * probably try for only so often before quitting.
  */

  /* Perform a basic check to see if this fd is open.  This does not
     guarantee it is the correct fd */

  if(fcntl(fd, F_GETFD) < 0)
    perror("Invalid FD.\n");

  while (!awake)
    {
      if (write(fd,&wup,sizeof(wup)) > 1)
        {

          LCA_LOG(DEBUG, "%s", "Device is awake.");
          // Using I2C Read
          if (read(fd,buf,sizeof(buf)) != 4)
            {
              /* ERROR HANDLING: i2c transaction failed */
              perror("Failed to read from the i2c bus.\n");
            }
          else
            {
              assert(lca_is_crc_16_valid(buf, 2, buf+2));
              awake = true;
            }
        }
    }

  return awake;

}

int
lca_sleep_device(int fd)
{

  unsigned char sleep_byte[] = {0x01};

  return write(fd, sleep_byte, sizeof(sleep_byte));


}

bool
lca_idle(int fd)
{

  bool result = false;

  uint8_t idle [] = {0x02};

  if (1 == write(fd, idle, sizeof(idle)))
    {
      result = true;
    }

  return result;

}

ssize_t
lca_write(int fd, const unsigned char *buf, unsigned int len)
{
  assert(NULL != buf);

  return write(fd, buf, len);

}

ssize_t
lca_read(int fd, unsigned char *buf, unsigned int len)
{
  assert(NULL != buf);

  return read(fd, buf, len);


}

ssize_t
lca_read_sleep(int fd,
                unsigned char *buf,
                unsigned int len,
                struct timespec wait_time)
{
  assert(NULL != buf);

  int bytes = -1;
  int attempt = 0;
  const int NUM_RETRIES = 3;
  struct timespec tim_rem;

  while (bytes < 0 && attempt < NUM_RETRIES)
    {
      if (0 > (bytes = read(fd, buf, len)))
        {
          LCA_LOG (DEBUG, "lca_read_sleep failed, retrying");
          if (0 != nanosleep (&wait_time , &tim_rem))
            {
              LCA_LOG (DEBUG, "Irritably woken from peaceful slumber.");
            }
        }

    }

  return bytes;
}

int
lca_atmel_setup(const char *bus, unsigned int addr)
{
#ifndef USE_KERNEL
    int fd = lca_setup(bus);

    lca_acquire_bus(fd, addr);

    lca_wakeup(fd);
#else
    int fd = open (bus, O_RDWR);
#endif

    return fd;

}

void
lca_atmel_teardown(int fd)
{
#ifndef USE_KERNEL
    lca_sleep_device(fd);
#endif

    close(fd);

}
