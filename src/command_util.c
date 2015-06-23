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
#include "command_util.h"
#include <stdlib.h>
#include <string.h>
#include "crc.h"
#include <assert.h>
#include "../libcryptoauth.h"

struct Command_ATSHA204
make_command (void)
{
    struct Command_ATSHA204 c = { .command = 0x03, .count = 0, .opcode = 0,
                                  .param1 = 0,
                                  .data = NULL, .data_len = 0};

    return c;

}


void set_param1 (struct Command_ATSHA204 *c, const uint8_t param1)
{
  assert (NULL != c);

  c->param1 = param1;

}

void set_param2 (struct Command_ATSHA204 *c, const uint8_t *param2)
{
  assert (NULL != c);
  assert (NULL != param2);

  c->param2[0] = param2[0];
  c->param2[1] = param2[1];

}

void set_opcode (struct Command_ATSHA204 *c, const uint8_t opcode)
{
  assert (NULL != c);

  c->opcode = opcode;

}

void set_data (struct Command_ATSHA204 *c,
               const uint8_t *data, const uint8_t len)
{
  assert (NULL != c);

  if (NULL == data || 0 == len)
    {
      c->data = NULL;
      c->data_len = 0;
    }
  else
    {
      c->data = malloc (len);
      assert (NULL != c->data);
      memcpy (c->data, data, len);
      c->data_len = len;
    }


}

void set_execution_time (struct Command_ATSHA204 *c, const unsigned int sec,
                        const unsigned long nano)
{
  assert (NULL != c);
  c->exec_time.tv_sec = sec;
  c->exec_time.tv_nsec = nano;

}

struct Command_ATSHA204
build_command (uint8_t opcode,
               uint8_t param1,
               uint8_t *param2,
               uint8_t *data,
               uint8_t len,
               unsigned int sec,
               unsigned long nano)
{
  struct Command_ATSHA204 c = make_command ();
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_opcode (&c, opcode);
  set_data (&c, data, len);
  set_execution_time (&c, sec, nano);

  return c;
}

void
lca_print_command (struct Command_ATSHA204 *c)
{
  assert (NULL != c);

  const char* opcode = NULL;

  LCA_LOG (DEBUG, "*** Printing Command ***");
  LCA_LOG (DEBUG, "Command: 0x%02X", c->command);
  LCA_LOG (DEBUG, "Count: 0x%02X", c->count);
  LCA_LOG (DEBUG, "OpCode: 0x%02X", c->opcode);

  switch (c->opcode)
    {
    case COMMAND_DERIVE_KEY:
      opcode = "Command Derive Key";
      break;
    case COMMAND_DEV_REV:
      opcode = "Command Dev Rev";
      break;
    case COMMAND_GEN_DIG:
      opcode = "Command Generate Digest";
      break;
    case COMMAND_HMAC:
      opcode = "Command HMAC";
      break;
    case COMMAND_CHECK_MAC:
      opcode = "Command Check MAC";
      break;
    case COMMAND_LOCK:
      opcode = "Command Lock";
      break;
    case COMMAND_MAC:
      opcode = "Command MAC";
      break;
    case COMMAND_NONCE:
      opcode = "Command NONCE";
      break;
    case COMMAND_PAUSE:
      opcode = "Command Pause";
      break;
    case COMMAND_RANDOM:
      opcode = "Command Random";
      break;
    case COMMAND_READ:
      opcode = "Command Read";
      break;
    case COMMAND_UPDATE_EXTRA:
      opcode = "Command Update Extra";
      break;
    case COMMAND_WRITE:
      opcode = "Command Write";
      break;
    case COMMAND_GEN_KEY:
      opcode = "Command Gen ECC Key";
      break;
    case COMMAND_ECC_SIGN:
      opcode = "Command ECC Sign Key";
      break;
    case COMMAND_ECC_VERIFY:
      opcode = "Command ECC Verify";
      break;
    case COMMAND_ECDH:
      opcode = "Command ECDH";
      break;
    default:
      assert (false);
    }
  LCA_LOG (DEBUG,"%s", opcode);
  LCA_LOG (DEBUG,"param1: 0x%02X", c->param1);
  LCA_LOG (DEBUG,"param2: 0x%02X 0x%02X", c->param2[0], c->param2[1]);
  if (c->data_len > 0)
    lca_print_hex_string ("Data", c->data, c->data_len);
  LCA_LOG (DEBUG,"CRC: 0x%02X 0x%02X", c->checksum[0], c->checksum[1]);
  LCA_LOG (DEBUG,"Wait time: %ld seconds %lu nanoseconds",
          c->exec_time.tv_sec, c->exec_time.tv_nsec);



}

enum LCA_STATUS_RESPONSE
lca_get_status_response(const uint8_t *rsp)
{
  const unsigned int OFFSET_TO_CRC = 2;
  const unsigned int OFFSET_TO_RSP = 1;
  const unsigned int STATUS_LENGTH = 4;

  if (!lca_is_crc_16_valid (rsp, STATUS_LENGTH - LCA_CRC_16_LEN,
                             rsp + OFFSET_TO_CRC))
    {
      LCA_LOG (DEBUG, "CRC Fail in status response");
      return RSP_COMM_ERROR;
    }

  return *(rsp + OFFSET_TO_RSP);

}

uint8_t
set_zone_bits (const enum DATA_ZONE zone)
{
    uint8_t z;

    switch (zone)
    {
    case CONFIG_ZONE:
        z = 0b00000000;
        break;
    case OTP_ZONE:
        z = 0b00000001;
        break;
    case DATA_ZONE:
        z = 0b00000010;
        break;
    default:
        assert (false);

    }

    return z;

}

uint8_t
slot_to_addr (const enum DATA_ZONE zone, const uint8_t slot)
{
    switch (zone)
    {
    case DATA_ZONE:
        assert (slot <= 15);
        break;

    case OTP_ZONE:
        assert (0 == slot || 1 == slot);
        break;

    case CONFIG_ZONE:
        assert (slot <= 2);
        break;

    default:
        assert (false);
    }

    uint8_t val = slot;

    val <<= 3;

    return val;

}
