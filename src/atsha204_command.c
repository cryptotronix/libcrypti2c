/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014-2015 Cryptotronix, LLC.
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

#include "config.h"
#include "atsha204_command.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../libcryptoauth.h"
#include "command_util.h"

struct Command_ATSHA204
lca_build_random_cmd (bool update_seed)
{
  uint8_t param2[2] = {0};
  uint8_t param1 = update_seed ? 0 : 1;

  struct Command_ATSHA204 c =
    build_command (COMMAND_RANDOM,
                   param1,
                   param2,
                   NULL, 0,
                   0, RANDOM_AVG_EXEC);

  return c;
}

struct lca_octet_buffer
lca_get_random (int fd, bool update_seed)
{
  uint8_t *random_buf = NULL;
  struct lca_octet_buffer buf = {0, 0};
  random_buf = lca_malloc_wipe (RANDOM_RSP_LENGTH);

  struct Command_ATSHA204 c = lca_build_random_cmd (update_seed);

  if (RSP_SUCCESS == lca_process_command (fd, &c, random_buf,
                                           RANDOM_RSP_LENGTH))
    {
      buf.ptr = random_buf;
      buf.len = RANDOM_RSP_LENGTH;
    }
  else
    {
      LCA_LOG (DEBUG, "Random command failed");
      free (random_buf);
    }

  return buf;



}

struct Command_ATSHA204
lca_build_read4_cmd (enum DATA_ZONE zone, uint8_t addr)
{

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);
  param2[0] = addr;

  struct Command_ATSHA204 c =
    build_command (COMMAND_READ,
                   param1,
                   param2,
                   NULL, 0,
                   0, READ_AVG_EXEC);

  return c;

}

bool
read4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t *buf)
{

  bool result = false;
  assert (NULL != buf);

  struct Command_ATSHA204 c = lca_build_read4_cmd (zone, addr);

  if (RSP_SUCCESS == lca_process_command (fd,
                                           &c,
                                           (uint8_t *)buf, sizeof (uint32_t)))
    {
      result = true;
    }

  return result;
}

bool
lca_read4 (int fd, enum DATA_ZONE zone, uint8_t addr[2], uint8_t buf[4])
{

  bool result = false;
  assert (NULL != buf);

  struct Command_ATSHA204 c = lca_build_read4_cmd (zone, addr[0]);

  /* hack, fix the addr */
  c.param2[0] = addr[0];
  c.param2[1] = addr[1];

  if (RSP_SUCCESS == lca_process_command (fd, &c, buf, 4))
    {
      result = true;
    }

  return result;
}

struct Command_ATSHA204
lca_build_read32_cmd (enum DATA_ZONE zone, uint8_t addr)
{
  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  uint8_t READ_32_MASK = 0b10000000;

  param1 |= READ_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c =
    build_command (COMMAND_READ,
                   param1,
                   param2,
                   NULL, 0,
                   0, READ_AVG_EXEC);

  return c;

}

struct lca_octet_buffer
read32 (int fd, enum DATA_ZONE zone, uint8_t addr)
{

  struct Command_ATSHA204 c = lca_build_read32_cmd (zone, addr);

  const unsigned int LENGTH_OF_RESPONSE = 32;
  struct lca_octet_buffer buf = lca_make_buffer (LENGTH_OF_RESPONSE);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, LENGTH_OF_RESPONSE))
    {
      lca_free_wipe (buf.ptr, LENGTH_OF_RESPONSE);
      buf.ptr = NULL;
      buf.len = 0;
    }

  return buf;
}

struct lca_octet_buffer
lca_read32 (int fd, enum DATA_ZONE zone, uint8_t addr[2])
{

  struct Command_ATSHA204 c = lca_build_read32_cmd (zone, addr[0]);

  /* hack, fix the addr */
  c.param2[0] = addr[0];
  c.param2[1] = addr[1];

  set_execution_time (&c, 0, 1000000);

  const unsigned int LENGTH_OF_RESPONSE = 32;
  struct lca_octet_buffer buf = lca_make_buffer (LENGTH_OF_RESPONSE);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, LENGTH_OF_RESPONSE))
    {
      lca_free_wipe (buf.ptr, LENGTH_OF_RESPONSE);
      buf.ptr = NULL;
      buf.len = 0;
    }

  return buf;
}


struct Command_ATSHA204
lca_build_write4_cmd (enum DATA_ZONE zone, uint8_t addr, uint32_t buf)
{

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  param2[0] = addr;

  struct Command_ATSHA204 c =
    build_command (COMMAND_WRITE,
                   param1,
                   param2,
                   (uint8_t *)&buf, sizeof (buf),
                   0, WRITE_AVG_EXEC);

  return c;

}

bool
write4 (int fd, enum DATA_ZONE zone, uint8_t addr, uint32_t buf)
{

  bool status = false;
  uint8_t recv = 0;

  struct Command_ATSHA204 c = lca_build_write4_cmd (zone, addr, buf);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &recv, sizeof (recv)))
  {
    if (0 == (int) recv)
      status = true;
  }

  return status;

}

struct Command_ATSHA204
lca_build_write32_cmd (const enum DATA_ZONE zone,
                        const uint8_t addr,
                        const struct lca_octet_buffer buf,
                        const struct lca_octet_buffer *mac)
{

  assert (NULL != buf.ptr);
  assert (32 == buf.len);
  if (NULL != mac)
    assert (NULL != mac->ptr);

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  struct lca_octet_buffer data = {0,0};

  if (NULL != mac)
    data = lca_make_buffer (buf.len + mac->len);
  else
    data = lca_make_buffer (buf.len);

  memcpy (data.ptr, buf.ptr, buf.len);
  if (NULL != mac && mac->len > 0)
    memcpy (data.ptr + buf.len, mac->ptr, mac->len);

  /* If writing 32 bytes, this bit must be set in param1 */
  uint8_t WRITE_32_MASK = 0b10000000;

  param1 |= WRITE_32_MASK;

  param2[0] = addr;

  struct Command_ATSHA204 c =
    build_command (COMMAND_WRITE,
                   param1,
                   param2,
                   data.ptr, data.len,
                   0, WRITE_AVG_EXEC);

  return c;

}

static struct Command_ATSHA204
lca_build_write32_nomac (const enum DATA_ZONE zone,
                         const uint8_t addr[2],
                         const struct lca_octet_buffer buf)
{

  assert (NULL != buf.ptr);
  assert (32 == buf.len);

  uint8_t param2[2] = {0};
  uint8_t param1 = set_zone_bits (zone);

  struct lca_octet_buffer data = {0,0};

  data = lca_make_buffer (buf.len);

  memcpy (data.ptr, buf.ptr, buf.len);

  /* If writing 32 bytes, this bit must be set in param1 */
  uint8_t WRITE_32_MASK = 0b10000000;

  param1 |= WRITE_32_MASK;

  param2[0] = addr[0];
  param2[1] = addr[1];

  struct Command_ATSHA204 c =
    build_command (COMMAND_WRITE,
                   param1,
                   param2,
                   data.ptr, data.len,
                   0, WRITE_AVG_EXEC);

  return c;

}

bool
lca_write_32_data_zone (const int fd,
                        const uint8_t addr[2],
                        const struct lca_octet_buffer buf)
{
  bool status = false;
  uint8_t recv = 0;

  struct Command_ATSHA204 c =
    lca_build_write32_nomac (DATA_ZONE,
                             addr,
                             buf);


  if (RSP_SUCCESS == lca_process_command (fd, &c, &recv, sizeof (recv)))
    {
      LCA_LOG (DEBUG, "Write 32 successful.");
      if (0 == (int) recv)
        status = true;
    }

  if (NULL != c.data)
    free (c.data);

  return status;
}

bool
lca_write32_cmd (const int fd,
                  const enum DATA_ZONE zone,
                  const uint8_t addr,
                  const struct lca_octet_buffer buf,
                  const struct lca_octet_buffer *mac)
{

  bool status = false;
  uint8_t recv = 0;

  struct Command_ATSHA204 c =
    lca_build_write32_cmd (zone,
                            addr,
                            buf,
                            mac);

  if (RSP_SUCCESS == lca_process_command (fd, &c, &recv, sizeof (recv)))
  {
    LCA_LOG (DEBUG, "Write 32 successful.");
    if (0 == (int) recv)
      status = true;
  }

  if (NULL != c.data)
    free (c.data);

  return status;
}

bool
lca_is_locked (int fd, enum DATA_ZONE zone)
{
  const uint8_t config_addr = 0x10;
  const uint8_t UNLOCKED = 0x55;
  bool result = true;
  const unsigned int CONFIG_ZONE_OFFSET = 23;
  const unsigned int DATA_ZONE_OFFSET = 22;
  unsigned int offset = 0;
  uint8_t * ptr = NULL;

  switch (zone)
    {
    case CONFIG_ZONE:
      offset = CONFIG_ZONE_OFFSET;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      offset = DATA_ZONE_OFFSET;
      break;
    default:
      assert (false);

    }

  struct lca_octet_buffer config_data = read32 (fd, CONFIG_ZONE, config_addr);

  if (config_data.ptr != NULL)
    {
      ptr = config_data.ptr + offset;
      if (UNLOCKED == *ptr)
        result = false;
      else
        result = true;

      lca_free_octet_buffer (config_data);
    }

  return result;
}

bool
lca_is_config_locked (int fd)
{
  return lca_is_locked (fd, CONFIG_ZONE);
}

bool
lca_is_data_locked (int fd)
{
  return lca_is_locked (fd, DATA_ZONE);
}


struct lca_octet_buffer
get_config_zone (int fd)
{
  const unsigned int SIZE_OF_CONFIG_ZONE = 128;
  const unsigned int NUM_OF_WORDS = SIZE_OF_CONFIG_ZONE / 4;

  struct lca_octet_buffer buf = lca_make_buffer (SIZE_OF_CONFIG_ZONE);
  uint8_t *write_loc = buf.ptr;

  unsigned int addr = 0;
  unsigned int word = 0;

  while (word < NUM_OF_WORDS)
    {
      addr = word * 4;
      read4 (fd, CONFIG_ZONE, word, (uint32_t*)(write_loc+addr));
      word++;
    }

  return buf;
}

struct lca_octet_buffer
get_otp_zone (int fd)
{
    const unsigned int SIZE_OF_OTP_ZONE = 64;
    const unsigned int SIZE_OF_READ = 32;
    const unsigned int SIZE_OF_WORD = 4;
    const unsigned int SECOND_WORD = (SIZE_OF_READ / SIZE_OF_WORD);

    struct lca_octet_buffer buf = lca_make_buffer (SIZE_OF_OTP_ZONE);
    struct lca_octet_buffer half;

    int x = 0;

    for (x=0; x < 2; x++ )
      {
        int addr = x * SECOND_WORD;
        int offset = x * SIZE_OF_READ;

        half = read32 (fd, OTP_ZONE, addr);
        if (NULL != half.ptr)
          {
            memcpy (buf.ptr + offset, half.ptr, SIZE_OF_READ);
            lca_free_octet_buffer (half);
          }
        else
          {
            lca_free_octet_buffer (buf);
            buf.ptr = NULL;
            return buf;
          }

      }

    return buf;
}

bool
lock (int fd, enum DATA_ZONE zone, uint16_t crc)
{

  uint8_t param1 = 0;
  uint8_t param2[2];
  uint8_t response;
  bool result = false;

  if (lca_is_locked (fd, zone))
    return true;

  memcpy (param2, &crc, sizeof (param2));

  const uint8_t CONFIG_MASK = 0;
  const uint8_t DATA_MASK = 1;

  switch (zone)
    {
    case CONFIG_ZONE:
      param1 |= CONFIG_MASK;
      break;
    case DATA_ZONE:
    case OTP_ZONE:
      param1 |= DATA_MASK;
      break;
    default:
      assert (false);
    }

  /* ignore the crc */
  param1 |= 0x80;
  crc = 0;

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

bool
lca_lock_data_zone (int fd)
{
  return lock (fd, DATA_ZONE, 0);
}

static bool
is_otp_read_only_mode (int fd)
{
  const uint8_t ADDR = 0x04;
  uint32_t word = 0;
  assert (read4 (fd, CONFIG_ZONE, ADDR, &word));

  uint8_t * byte = (uint8_t *)&word;

  const unsigned int OFFSET_TO_OTP_MODE = 2;
  const unsigned int OTP_READ_ONLY_MODE = 0xAA;

  return OTP_READ_ONLY_MODE == byte[OFFSET_TO_OTP_MODE] ? true : false;


}


bool
set_otp_zone (int fd, struct lca_octet_buffer *otp_zone)
{

  assert (NULL != otp_zone);

  const unsigned int SIZE_OF_WRITE = 32;
  /* The device must be using an OTP read only mode */

  if (!is_otp_read_only_mode (fd))
    assert (false);

  /* The writes must be done in 32 bytes blocks */

  uint8_t nulls[SIZE_OF_WRITE];
  uint8_t part1[SIZE_OF_WRITE];
  uint8_t part2[SIZE_OF_WRITE];
  struct lca_octet_buffer buf = {0,0};
  lca_wipe (nulls, SIZE_OF_WRITE);
  lca_wipe (part1, SIZE_OF_WRITE);
  lca_wipe (part2, SIZE_OF_WRITE);

  /* Simple check to make sure PACKAGE_VERSION isn't too long */
  assert (strlen (PACKAGE_VERSION) < 10);

  /* Setup the fixed OTP data zone */
  sprintf ((char *)part1, "CRYPTOTRONIX ECLET REV: A");
  sprintf ((char *)part2, "SOFTWARE VERSION: %s", PACKAGE_VERSION);

  bool success = true;

  buf.ptr = nulls;
  buf.len = sizeof (nulls);

  /* Fill the OTP zone with blanks from their default FFFF */
  success = lca_write32_cmd (fd, OTP_ZONE, 0, buf, NULL);

  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                                buf, NULL);

  /* Fill in the data */
  buf.ptr = part1;
  LCA_LOG (DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, 0, buf, NULL);
  buf.ptr = part2;
  LCA_LOG (DEBUG, "Writing: %s", buf.ptr);
  if (success)
    success = lca_write32_cmd (fd, OTP_ZONE, SIZE_OF_WRITE / sizeof (uint32_t),
                                buf, NULL);

  /* Lastly, copy the OTP zone into one contiguous buffer.
     Ironically, the OTP can't be read while unlocked. */
  if (success)
    {
      otp_zone->len = SIZE_OF_WRITE * 2;
      otp_zone->ptr = lca_malloc_wipe (otp_zone->len);
      memcpy (otp_zone->ptr, part1, SIZE_OF_WRITE);
      memcpy (otp_zone->ptr + SIZE_OF_WRITE, part2, SIZE_OF_WRITE);
    }
  return success;
}


struct lca_octet_buffer
get_serial_num (int fd)
{
  struct lca_octet_buffer serial;
  const unsigned int len = sizeof (uint32_t) * 2 + 1;
  serial.ptr = lca_malloc_wipe (len);
  serial.len = len;

  uint32_t word = 0;

  const uint8_t SERIAL_PART1_ADDR = 0x00;
  const uint8_t SERIAL_PART2_ADDR = 0x02;
  const uint8_t SERIAL_PART3_ADDR = 0x03;

  read4 (fd, CONFIG_ZONE, SERIAL_PART1_ADDR, &word);
  memcpy (serial.ptr, &word, sizeof (word));

  read4 (fd, CONFIG_ZONE, SERIAL_PART2_ADDR, &word);
  memcpy (serial.ptr + sizeof (word), &word, sizeof (word));

  read4 (fd, CONFIG_ZONE, SERIAL_PART3_ADDR, &word);

  uint8_t * ptr = (uint8_t *)&word;

  memcpy (serial.ptr + len - 1, ptr, 1);

  return serial;

}


enum DEVICE_STATE
lca_get_device_state (int fd)
{
  bool config_locked;
  bool data_locked;
  enum DEVICE_STATE state = STATE_FACTORY;

  config_locked = lca_is_config_locked (fd);
  data_locked = lca_is_data_locked (fd);

  if (!config_locked && !data_locked)
    state = STATE_FACTORY;
  else if (config_locked && !data_locked)
    state = STATE_INITIALIZED;
  else if (config_locked && data_locked)
    state = STATE_PERSONALIZED;
  else
    assert (false);

  return state;

}


struct lca_octet_buffer
gen_nonce (int fd, struct lca_octet_buffer data)
{
  const unsigned int EXTERNAL_INPUT_LEN = 32;
  const unsigned int NEW_NONCE_LEN = 20;

  assert (NULL != data.ptr && (EXTERNAL_INPUT_LEN == data.len ||
                               NEW_NONCE_LEN == data.len));

  uint8_t param2[2] = {0};
  uint8_t param1 = 0;

  unsigned int rsp_len = 0;

  if (EXTERNAL_INPUT_LEN == data.len)
    {
      const unsigned int PASS_THROUGH_MODE = 3;
      const unsigned int RSP_LENGTH = 1;
      param1 = PASS_THROUGH_MODE;
      rsp_len = RSP_LENGTH;
    }
  else
    {
      const unsigned int COMBINE_AND_UPDATE_SEED = 0;
      const unsigned int RSP_LENGTH = 32;
      param1 = COMBINE_AND_UPDATE_SEED;
      rsp_len = RSP_LENGTH;
    }

  struct lca_octet_buffer buf = lca_make_buffer (rsp_len);

  struct Command_ATSHA204 c = make_command ();

  set_opcode (&c, COMMAND_NONCE);
  set_param1 (&c, param1);
  set_param2 (&c, param2);
  set_data (&c, data.ptr, data.len);
  set_execution_time (&c, 0, NONCE_AVG_EXEC);

  if (RSP_SUCCESS != lca_process_command (fd, &c, buf.ptr, buf.len))
    {
      LCA_LOG (DEBUG, "Nonce command failed");
      lca_free_octet_buffer (buf);
      buf.ptr = NULL;
    }

  return buf;



}

struct lca_octet_buffer
get_nonce (int fd)
{
  struct lca_octet_buffer otp;
  struct lca_octet_buffer nonce = {0, 0};
  const unsigned int MIX_DATA_LEN = 20;

  otp = get_otp_zone (fd);
  unsigned int otp_len = otp.len;

  if (otp.len > MIX_DATA_LEN && otp.ptr != NULL)
    {
      otp.len = MIX_DATA_LEN;
      nonce = gen_nonce (fd, otp);
      otp.len = otp_len;

    }

  lca_free_octet_buffer (otp);

  return nonce;
}


bool
load_nonce (int fd, struct lca_octet_buffer data)
{
  assert (data.ptr != NULL && data.len == 32);

  struct lca_octet_buffer rsp = gen_nonce (fd, data);

  if (NULL == rsp.ptr || *rsp.ptr != 0)
    return false;
  else
    return true;

}
