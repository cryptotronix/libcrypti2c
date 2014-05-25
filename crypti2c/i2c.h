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

#ifndef I2C_H
#define I2C_H

#include <unistd.h>
#include <stdbool.h>

/**
 * Open the I2C bus
 *
 * @param bus The desired I2C bus.
 *
 * @return An open file descriptor or the program will exit.
 */
int
ci2c_setup (const char* bus);

void
ci2c_acquire_bus (int fd, int addr);

bool
ci2c_wakeup (int fd);

int
ci2c_sleep_device (int fd);

ssize_t
ci2c_write(int fd, unsigned char *buf, unsigned int len);

ssize_t
ci2c_read(int fd, unsigned char *buf, unsigned int len);

/**
 * Idle the device. It will only respond to a wakeup after
 * this. However, internal volatile memory is preserved. Returns true
 * if successful.
 *
 * @param fd The open file descriptor
 */
bool
ci2c_idle(int fd);

/**
 * Sets up the device for communication.
 *
 * @param bus The I2C bus.
 * @param addr The address of the device
 *
 * @return An open file descriptor or -1 on error
 */
int
ci2c_atmel_setup(const char *bus, unsigned int addr);

/**
 * Sleeps the device and closes the file descriptor.
 *
 * @param fd The open file descriptor
 *
 */
void
ci2c_atmel_teardown(int fd);
#endif /* I2C_H */
