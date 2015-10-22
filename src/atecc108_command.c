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
#include "config.h"
#include "atsha204_command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "../libcryptoauth.h"
#include "command_util.h"


struct lca_octet_buffer
lca_gen_ecc_key (int fd, uint8_t key_id, bool private)
{

  assert (key_id <= 15);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  param2[0] = key_id;

  if (private)
    {
      param1 = 0x04; /* Private key */
    }
  else
    {
      param1 = 0x00; /* Gen public key from private key in the slot */
    }

  struct lca_octet_buffer pub_key = lca_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_GEN_KEY);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, GEN_KEY_AVG_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, pub_key.ptr, pub_key.len))
    {
      LCA_LOG (DEBUG, "Gen key success");
    }
  else
    {
      LCA_LOG (DEBUG, "Gen key failure");
      lca_free_octet_buffer (pub_key);
      pub_key.ptr = NULL;
    }

  return pub_key;

}


struct lca_octet_buffer
lca_ecc_sign (int fd, uint8_t key_id)
{

  assert (key_id <= 15);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x80; /* external signatures only */

  param2[0] = key_id;

  struct lca_octet_buffer signature = lca_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECC_SIGN);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, ECC_SIGN_MAX_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, signature.ptr, signature.len))
    {
      LCA_LOG (DEBUG, "Sign success");
    }
  else
    {
      LCA_LOG (DEBUG, "Sign failure");
      lca_free_octet_buffer (signature);
      signature.ptr = NULL;
    }

  return signature;


}


bool
lca_ecc_verify (int fd,
                 struct lca_octet_buffer pub_key,
                 struct lca_octet_buffer signature)
{

  assert (NULL != signature.ptr);
  assert (64 == signature.len); /* P256 signatures are 64 bytes */

  assert (NULL != pub_key.ptr);
  assert (64 == pub_key.len); /* P256 Public Keys are 64 bytes */

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x02; /* Currently only support external keys */

  param2[0] = 0x04; /* Currently only support P256 Keys */

  struct lca_octet_buffer payload =
    lca_make_buffer (signature.len + pub_key.len);

  memcpy (payload.ptr, signature.ptr, signature.len);
  memcpy (payload.ptr + signature.len, pub_key.ptr, pub_key.len);

  uint8_t result = 0xFF;
  bool verified = false;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECC_VERIFY);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, payload.ptr, payload.len);
  set_execution_time (&c, 0, ECC_VERIFY_MAX_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &result, sizeof(result)))
    {
      LCA_LOG (DEBUG, "Verify success");
      verified = true;
    }
  else
    {
      LCA_LOG (DEBUG, "Verify failure");
    }

  lca_free_octet_buffer (payload);

  return verified;


}

struct lca_octet_buffer
lca_ecdh (int fd, uint8_t slot,
          struct lca_octet_buffer x, struct lca_octet_buffer y)
{
  assert (slot <= 15);
  assert (32 == x.len);
  assert (32 == y.len);
  assert (x.ptr);
  assert (y.ptr);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  param2[0] = slot;

  struct lca_octet_buffer shared_secret = lca_make_buffer (32);
  struct lca_octet_buffer data = lca_make_buffer (64);

  memcpy (data.ptr, x.ptr, x.len);
  memcpy (data.ptr + x.len, y.ptr, y.len);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECDH);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, data.ptr, data.len);
  set_execution_time (&c, 0, ECC_SIGN_MAX_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c,
                                          shared_secret.ptr, shared_secret.len))
    {
      LCA_LOG (DEBUG, "ECDH success");
    }
  else
    {
      LCA_LOG (DEBUG, "ECDH failure");
      lca_free_octet_buffer (shared_secret);
      shared_secret.ptr = NULL;
    }

  lca_free_octet_buffer (data);

  return shared_secret;
}

bool
lca_slot_lock (int fd, uint8_t slot)
{

  uint8_t param1 = 0;
  uint8_t param2[] = {0, 0};
  uint8_t response;
  bool result = false;

  const uint8_t NO_CRC_MASK = 0x80;
  const uint8_t SLOT_LOCK_MASK = 2;
  uint8_t slot_mask = slot << 2;


  /* ignore the crc */
  param1 = NO_CRC_MASK | SLOT_LOCK_MASK | slot_mask;

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_LOCK);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, LOCK_AVG_EXEC);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &response, sizeof (response)))
    {
      if (0 == response)
        {
          result = true;
          LCA_LOG (DEBUG, "Lock Successful");
        }
      else
        {
          LCA_LOG (DEBUG, "Lock Failed");
        }
    }


  return result;

}
