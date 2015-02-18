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

#ifndef I2C_H
#define I2C_H

#include <unistd.h>
#include <stdbool.h>
#include <time.h>

/**
 * Open the I2C bus
 *
 * @param bus The desired I2C bus.
 *
 * @return An open file descriptor or the program will exit.
 */
int
lca_setup (const char* bus);

void
lca_acquire_bus (int fd, int addr);

bool
lca_wakeup (int fd);

int
lca_sleep_device (int fd);

ssize_t
lca_write(int fd, const unsigned char *buf, unsigned int len);

ssize_t
lca_read(int fd, unsigned char *buf, unsigned int len);

/**
 * Idle the device. It will only respond to a wakeup after
 * this. However, internal volatile memory is preserved. Returns true
 * if successful.
 *
 * @param fd The open file descriptor
 */
bool
lca_idle(int fd);

/**
 * Sets up the device for communication.
 *
 * @param bus The I2C bus.
 * @param addr The address of the device
 *
 * @return An open file descriptor or -1 on error
 */
int
lca_atmel_setup(const char *bus, unsigned int addr);

/**
 * Sleeps the device and closes the file descriptor.
 *
 * @param fd The open file descriptor
 *
 */
void
lca_atmel_teardown(int fd);

ssize_t
lca_read_sleep(int fd,
                unsigned char *buf,
                unsigned int len,
                struct timespec wait_time);
#endif /* I2C_H */
