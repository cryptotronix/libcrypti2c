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

#include "command_adaptation.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crc.h"
#include <assert.h>
#include "util.h"
#include "log.h"
#include "command_util.h"

const char*
status_to_string (enum CI2C_STATUS_RESPONSE rsp)
{
  const char *rsp_string = NULL;

  switch (rsp)
    {
    case RSP_SUCCESS:
      rsp_string = "Response Success";
      break;
    case RSP_CHECKMAC_MISCOMPARE:
      rsp_string = "Response CheckMac Miscompare";
      break;
    case RSP_PARSE_ERROR:
      rsp_string = "Response Parse Error";
      break;
    case RSP_EXECUTION_ERROR:
      rsp_string = "Response Execution Error";
      break;
    case RSP_AWAKE:
      rsp_string = "Response Awake";
      break;
    case RSP_COMM_ERROR:
      rsp_string = "Response Communication Error";
      break;
    case RSP_NAK:
      rsp_string = "Response NAK";
      break;
    case ECC_FAULT:
      rsp_string = "ECC Fault";
      break;
    default:
      assert (false);

    }

  return rsp_string;
}


enum CI2C_STATUS_RESPONSE
ci2c_process_command (int fd, struct Command_ATSHA204 *c,
                      uint8_t* rec_buf, unsigned int recv_len)
{
  unsigned int c_len = 0;
  uint8_t *serialized;

  assert (NULL != c);
  assert (NULL != rec_buf);

  c_len = ci2c_serialize_command (c, &serialized);

  enum CI2C_STATUS_RESPONSE rsp = ci2c_send_and_receive (fd,
                                                         serialized,
                                                         c_len,
                                                         rec_buf,
                                                         recv_len,
                                                         &c->exec_time);

  ci2c_free_wipe (serialized, c_len);

  return rsp;


}

enum CI2C_STATUS_RESPONSE
ci2c_send_and_receive (int fd,
                       const uint8_t *send_buf,
                       unsigned int send_buf_len,
                       uint8_t *recv_buf,
                       unsigned int recv_buf_len,
                       struct timespec *wait_time)
{
  enum CI2C_STATUS_RESPONSE rsp = RSP_COMM_ERROR;
  ssize_t result = 0;

  assert (NULL != send_buf);
  assert (NULL != recv_buf);
  assert (NULL != wait_time);

  result = write (fd, send_buf, send_buf_len);

  if (result == send_buf_len)
    {
      result = read (fd, recv_buf, recv_buf_len);

      if (result == 1)
        {
          CI2C_LOG (DEBUG, "Command Response: %s", status_to_string (recv_buf[0]));
          rsp = recv_buf[0];
        }
      else
        {
          rsp = RSP_SUCCESS;
        }
    }


  return rsp;

}

unsigned int
ci2c_serialize_command (struct Command_ATSHA204 *c, uint8_t **serialized)
{
  unsigned int total_len = 0;
  uint8_t *data;

  assert (NULL != c);
  assert (NULL != serialized);

  total_len = sizeof (c->opcode) + sizeof (c->param1) + sizeof (c->param2)
    + c->data_len;

  data = (uint8_t*)malloc (total_len);

  assert (NULL != data);

  /* copy over the command */
  data[0] = c->opcode;
  data[1] = c->param1;
  data[2] = c->param2[0];
  data[3] = c->param2[1];

  if (c->data_len > 0)
    memcpy (&data[4], c->data, c->data_len);

  *serialized = data;

  return total_len;

}
