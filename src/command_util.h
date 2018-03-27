/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2018 Cryptotronix, LLC.
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
#ifndef COMMANDUTIL_H
#define COMMANDUTIL_H

#include "command_adaptation.h"

/* Command OPCODES */
#define COMMAND_DERIVE_KEY      0x1C
#define COMMAND_DEV_REV         0x30
#define COMMAND_GEN_DIG         0x15
#define COMMAND_HMAC            0x11
#define COMMAND_CHECK_MAC       0x28
#define COMMAND_LOCK            0x17
#define COMMAND_MAC             0x08
#define COMMAND_NONCE           0x16
#define COMMAND_PAUSE           0x01
#define COMMAND_RANDOM          0x1B
#define COMMAND_READ            0x02
#define COMMAND_UPDATE_EXTRA    0x20
#define COMMAND_WRITE           0x12
#define COMMAND_GEN_KEY         0x40
#define COMMAND_ECC_SIGN        0x41
#define COMMAND_ECC_VERIFY      0x45
#define COMMAND_ECDH            0x43

/* Command responses */
#define SUCCESS_RESPONSE        0x00
#define CHECKMAC_MISCOMPARE     0x01
#define PARSE_ERROR             0x03
#define EXECUTION_ERROR         0x0F
#define IM_AWAKE                0x11
#define CRC_OR_COMM_ERROR       0xFF
#define ECC_ERROR               0x05

#define MAX_NUM_DATA_SLOTS      16

/* Slot config definition */
#define MAX_SLOTS 16


/* Random Command, i.e. actual random not a random command, ha! */

#define RANDOM_UPDATE_SEED      0
#define RANDOM_NO_UPDATE_SEED   1
#define RANDOM_RSP_LENGTH       32

/* Read Command Options */

#define READ4_LENGTH            4
#define READ32_LENGTH           32

/* Execution Times (all times in nanosecs) */
#define DERIVE_KEY_AVG_EXEC 14000000
#define MAC_AVG_EXEC 12000000
#define DEV_REV_AVG_EXEC 400000
#define GEN_DIG_AVG_EXEC 11000000
#define HMAC_AVG_EXEC 27000000
#define CHECK_MAC_AVG_EXEC 12000000
#define LOCK_AVG_EXEC 5000000
#define NONCE_AVG_EXEC 22000000
#define PAUSE_AVG_EXEC 400000
#define READ_AVG_EXEC 400000
#define UPDATE_EXTRA_AVG_EXEC 8000000
#define WRITE_AVG_EXEC 4000000
#define RANDOM_AVG_EXEC 11000000
#define GEN_KEY_AVG_EXEC 9000000
#define ECC_SIGN_AVG_EXEC 33000000
#define ECC_VERYFY_AVG_EXEC 36000000

#define DERIVE_KEY_MAX_EXEC 62000000
#define DEV_REV_MAX_EXEC 2000000
#define GEN_DIG_MAX_EXEC 43000000
#define HMAC_MAX_EXEC 69000000
#define CHECK_MAC_MAX_EXEC 38000000
#define LOCK_MAX_EXEC 24000000
#define MAC_MAX_EXEC 35000000
#define NONCE_MAX_EXEC 60000000
#define PAUSE_MAX_EXEC 2000000
#define RANDOM_MAX_EXEC 50000000
#define READ_MAX_EXEC 4000000
#define UPDATE_EXTRA_MAX_EXEC 12000000
#define WRITE_MAX_EXEC    42000000
#define GEN_KEY_MAX_EXEC  96000000
#define ECC_SIGN_MAX_EXEC 38000000
#define ECC_VERIFY_MAX_EXEC 73000000

struct Command_ATSHA204
make_command (void) __attribute__ ((const));

struct Command_ATSHA204
build_command (uint8_t opcode,
               uint8_t param1,
               uint8_t *param2,
               uint8_t *data,
               uint8_t len,
               unsigned int sec,
               unsigned long nano);


/**
 * Sets the param1 field in the command structure.
 *
 * @param c The Command structure
 * @param param1 The single byte parameter 1 field.
 */
void set_param1 (struct Command_ATSHA204 *c, const uint8_t param1);

/**
 * Sets the param2 field in the command structure. It is a two byte
 * field, which is *little endian*.
 *
 * @param c The command structure
 * @param param2 The two byte array to set.
 */
void set_param2 (struct Command_ATSHA204 *c, const uint8_t *param2);

/**
 * Sets the opcode field for the command
 *
 * @param c The Command structure
 * @param opcode The byte containing the opcode
 */
void set_opcode (struct Command_ATSHA204 *c, const uint8_t opcode);

/**
 * Sets the data field for the command. The caller must manage the
 * memory. This function will not attempt to free or allocate memory.
 *
 * @param c The command structure
 * @param data The pointer to the data to set.
 * @param len The length of the data to set.
 */
void set_data (struct Command_ATSHA204 *c,
               const uint8_t *data,
               const uint8_t len);

/**
 * Sets the expected execution time of the command. This is the time
 * to wait for a response.
 *
 * @param c The command structure
 * @param sec The amount of time in seconds.
 * @param nano The amount of time in nanoseconds.
 */
void set_execution_time (struct Command_ATSHA204 *c,
                         const unsigned int sec,
                         const unsigned long nano);

/**
 * Convert the zone into the appropriate bit mask.
 *
 * @param zone the zone enum
 *
 * @return A byte with the appropriate bit field set
 */
uint8_t
set_zone_bits (const enum DATA_ZONE zone)
  __attribute__ ((pure));

/**
 * Serialize the slot byte based on the data zone and the logical slot number.
 *
 * @param zone The zone where this slot lives.
 * @param slot The slot number.
 *
 * @return The serialized byte for this slot.
 */
uint8_t
slot_to_addr (const enum DATA_ZONE zone, const uint8_t slot)
  __attribute__ ((pure));
#endif
