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

#include "atsha204_command.h"
#include "atecc108_command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "log.h"


struct ci2c_octet_buffer
ci2c_gen_ecc_key (int fd, uint8_t key_id, bool private)
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

  struct ci2c_octet_buffer pub_key = ci2c_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_GEN_KEY);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, GEN_KEY_AVG_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, pub_key.ptr, pub_key.len))
    {
      CI2C_LOG (DEBUG, "Gen key success");
    }
  else
    {
      CI2C_LOG (DEBUG, "Gen key failure");
      ci2c_free_octet_buffer (pub_key);
      pub_key.ptr = NULL;
    }

  return pub_key;

}


struct ci2c_octet_buffer
ci2c_ecc_sign (int fd, uint8_t key_id)
{

  assert (key_id <= 15);

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x80; /* external signatures only */

  param2[0] = key_id;

  struct ci2c_octet_buffer signature = ci2c_make_buffer (64);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_ECC_SIGN);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, NULL, 0);
  set_execution_time (&c, 0, ECC_SIGN_MAX_EXEC);

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, signature.ptr, signature.len))
    {
      CI2C_LOG (DEBUG, "Sign success");
    }
  else
    {
      CI2C_LOG (DEBUG, "Sign failure");
      ci2c_free_octet_buffer (signature);
      signature.ptr = NULL;
    }

  return signature;


}


bool
ci2c_ecc_verify (int fd,
                 struct ci2c_octet_buffer pub_key,
                 struct ci2c_octet_buffer signature)
{

  assert (NULL != signature.ptr);
  assert (64 == signature.len); /* P256 signatures are 64 bytes */

  assert (NULL != pub_key.ptr);
  assert (64 == pub_key.len); /* P256 Public Keys are 64 bytes */

  uint8_t param2[2] = {0};
  uint8_t param1 = 0x02; /* Currently only support external keys */

  param2[0] = 0x04; /* Currently only support P256 Keys */

  struct ci2c_octet_buffer payload =
    ci2c_make_buffer (signature.len + pub_key.len);

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

  if (RSP_SUCCESS == ci2c_process_command (fd, &c, &result, sizeof(result)))
    {
      CI2C_LOG (DEBUG, "Verify success");
      verified = true;
    }
  else
    {
      CI2C_LOG (DEBUG, "Verify failure");
    }

  ci2c_free_octet_buffer (payload);

  return verified;


}
