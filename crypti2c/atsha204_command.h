/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
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

#ifndef COMMAND_H
#define COMMAND_H

#include <time.h>
#include <stdbool.h>
#include <stdint.h>
#include "command_util.h"
#include "util.h"

/* Random Commands */

struct Command_ATSHA204
ci2c_build_random_cmd (bool update_seed);

/**
 * Get 32 bytes of random data from the device
 *
 * @param fd The open file descriptor
 * @param update_seed True updates the seed.  Do this sparingly.
 *
 * @return A malloc'ed buffer with random data.
 */
struct ci2c_octet_buffer
get_random (int fd, bool update_seed);


/**
 * Builds the command structure for a read4 command.
 *
 * @param zone The zone from which to read.
 * @param addr The desired read address.
 *
 * @return The populated command structure.
 */
struct Command_ATSHA204
ci2c_build_read4_cmd (enum DATA_ZONE zone, uint8_t addr);

/**
 * Read four bytes from the device.
 *
 * @param fd The open file descriptor.
 * @param zone The zone from which to read.  In some configurations,
 * four byte reads are not allowed.
 * @param addr The address from which to read.  Consult the data sheet
 * for address conversions.
 * @param buf A non-null pointer to the word to fill in.
 *
 * @return True if successful other false and buf should not be investigated.
 */
bool
read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf);

/**
 * Write four bytes to the device
 *
 * @param fd The open file descriptor
 * @param zone The zone to which to write
 * @param addr The address to write to, consult the data sheet for
 * address conversions.
 * @param buf The data to write.  Passed by value.
 *
 * @return True if successful.
 */
bool
write4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf);

/**
 * Write 32 bytes to the device.
 *
 * @param fd The open file descriptor.
 * @param zone The data zone to which to write
 * @param addr The address to write to.
 * @param buf The buffer to write, passed by value.  Buf.ptr should be
 * a valid pointer to the data and buf.len must be 32.
 * @param mac An optional mac for encrypted writes.
 *
 * @return True if successful.
 */
bool
write32 (int fd, enum DATA_ZONE zone, uint8_t addr,
         struct ci2c_octet_buffer buf, struct ci2c_octet_buffer *mac);

/**
 * Performs the nonce operation on the device.  Depending on the data
 * parameter, this command will either generate a new nonce or combine
 * an external value.
 *
 * @param fd The open file descriptor
 * @param data If 32 bytes, this command will load the 32 byte data
 * into the temp key register directly.  If 20 bytes, it will be
 * combined per the manual and 32 bytes of random data will be returned.
 *
 * @return If data is 32 bytes, it will return a buffer of size 1 with
 * a single 0 byte.  Otherwise, it returns a 32 byte random number.
 */
struct ci2c_octet_buffer
gen_nonce (int fd, struct ci2c_octet_buffer data);

/**
 * Generates a new nonce from the device.  This will combine the OTP
 * zone with a random number to generate the nonce.
 *
 * @param fd The open file descriptor.
 *
 * @return A 32 byte malloc'd buffer if successful.
 */
struct ci2c_octet_buffer
get_nonce (int fd);

/**
 * Set the configuration zone based.  This function will setup the
 * configuration zone, and thus the device, to a fixed configuration.
 *
 * @param fd The open file descriptor.
 *
 * @return True if succesful, otherwise false
 */
bool
set_config_zone (int fd);

/**
 * Programs the OTP zone with fixed data
 *
 * @param fd The open file descriptor
 * @param otp_zone A pointer to an octet buffer that will be malloc'd
 * and filled in with the OTP Zone contents if successful
 *
 * @return True if the OTP zone has been written.
 */
bool
set_otp_zone (int fd, struct ci2c_octet_buffer *otp_zone);

/**
 *
 *
 * @param fd The open file descriptor
 *
 * @return True if the configuration zone is locked
 */
bool
is_config_locked (int fd);

/**
 *
 *
 * @param fd The open file descriptor
 *
 * @return True if the data zone is locked
 */
bool
is_data_locked (int fd);

/**
 * Returns the entire configuration zone.
 *
 * @param fd The open file descriptor
 *
 * @return A malloc'ed buffer containing the entire configuration
 * zone.
 */
struct ci2c_octet_buffer
get_config_zone (int fd);

/**
 * Returns the entire OTP zone.
 *
 * @param fd The open file descriptor.
 *
 * @return A malloc'ed buffer containing the entire OTP zone.
 */
struct ci2c_octet_buffer
get_otp_zone (int fd);

/**
 * Locks the specified zone.
 *
 * @param fd The open file descriptor
 * @param zone The zone to lock.  Either CONFIG_ZONE or (DATA_ZONE or
 * OTP_ZONE). The later will be locked together
 * @param crc The crc16 of the respective zone(s)
 *
 * @return True if now locked.
 */
bool
lock (int fd, enum DATA_ZONE zone, uint16_t crc);

/**
 * Retrieve the device's serial number
 *
 * @param fd An open file descriptor
 *
 * @return a malloc'd buffer with the serial number.
 */
struct ci2c_octet_buffer
get_serial_num (int fd);

/**
 * Reads 32 Bytes from the address
 *
 * @param fd The open file descriptor
 * @param zone The zone to read from
 * @param addr The address to read from
 *
 * @return 32 bytes of data or buf.ptr will be null on an error
 */
struct ci2c_octet_buffer
read32 (int fd, enum DATA_ZONE zone, uint8_t addr);


enum DEVICE_STATE
{
  STATE_FACTORY = 0,            /**< Config zone, data and OTP zones
                                    are unlocked */
  STATE_INITIALIZED,            /**< Config zone locked, data and OTP
                                    zones are unlockded */
  STATE_PERSONALIZED            /**< Config, data, and OTP zones are locked */
};

/**
 * Returns the logical state of the device based on the config, data,
 * and OTP zones
 *
 * @param fd The open file descriptor
 *
 * @return The devie state
 */
enum DEVICE_STATE
get_device_state (int fd);

/**
 * Converts the slot number to the correct address byte
 *
 * @param zone The zone enumeration
 * @param slot The slot number
 *
 * @return The formatted byte, it will assert a failure if not correct.
 */
uint8_t
slot_to_addr (enum DATA_ZONE zone, uint8_t slot);



bool
load_nonce (int fd, struct ci2c_octet_buffer data);



#endif /* COMMAND_H */
