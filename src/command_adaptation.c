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

#include "command_adaptation.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef USE_KERNEL
#include "i2c.h"
#endif
#include "crc.h"
#include <assert.h>
#include "util.h"
#include "log.h"
#include "command_util.h"

const char*
status_to_string (enum LCA_STATUS_RESPONSE rsp)
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


enum LCA_STATUS_RESPONSE
lca_process_command (int fd, struct Command_ATSHA204 *c,
                      uint8_t* rec_buf, unsigned int recv_len)
{
  unsigned int c_len = 0;
  uint8_t *serialized;

  assert (NULL != c);
  assert (NULL != rec_buf);

  c_len = lca_serialize_command (c, &serialized);

  enum LCA_STATUS_RESPONSE rsp = lca_send_and_receive (fd,
                                                         serialized,
                                                         c_len,
                                                         rec_buf,
                                                         recv_len,
                                                         &c->exec_time);

  lca_free_wipe (serialized, c_len);

  return rsp;


}

enum LCA_STATUS_RESPONSE
lca_send_and_receive (int fd,
                       const uint8_t *send_buf,
                       unsigned int send_buf_len,
                       uint8_t *recv_buf,
                       unsigned int recv_buf_len,
                       struct timespec *wait_time)
{
#ifndef USE_KERNEL
  struct timespec tim_rem;
  enum LCA_STATUS_RESPONSE rsp = RSP_AWAKE;
  const unsigned int NUM_RETRIES = 10;
  unsigned int x = 0;
  ssize_t result = 0;

  assert (NULL != send_buf);
  assert (NULL != recv_buf);
  assert (NULL != wait_time);

  /* Send the data at first.  During a read, if the device responds
  with an "I'm Awake" flag, we've lost synchronization, so send the
  data again in that case only.  Arbitrarily retry this procedure
  NUM_RETRIES times */
  for (x=0; x < NUM_RETRIES && rsp == RSP_AWAKE; x++)
    {
      lca_print_hex_string ("Sending", send_buf, send_buf_len);

      result = lca_write (fd,
                           send_buf,
                           send_buf_len);

      if (result > 1)
        {
          do
            {
              nanosleep (wait_time , &tim_rem);
            }
          while ((rsp = lca_read_and_validate (fd, recv_buf, recv_buf_len))
                 == RSP_NAK);
          LCA_LOG (DEBUG, "Command Response: %s", status_to_string (rsp));
        }
      else
        {
          perror ("Send failed\n");
          exit (1);
        }


    }
#else
  enum LCA_STATUS_RESPONSE rsp = RSP_COMM_ERROR;
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
          LCA_LOG (DEBUG, "Command Response: %s", status_to_string (recv_buf[0]));
          rsp = recv_buf[0];
        }
      else
        {
          rsp = RSP_SUCCESS;
        }
    }
  else
    {
      LCA_LOG (DEBUG, "Write failed: %d\n", result);
    }
#endif

  return rsp;
}

unsigned int
lca_serialize_command (struct Command_ATSHA204 *c, uint8_t **serialized)
{
#ifndef USE_KERNEL
  unsigned int total_len = 0;
  unsigned int crc_len = 0;
  unsigned int crc_offset = 0;
  uint8_t *data;
  uint16_t *crc;


  assert (NULL != c);
  assert (NULL != serialized);

  total_len = sizeof (c->command) + sizeof (c->count) +sizeof (c->opcode) +
    sizeof (c->param1) + sizeof (c->param2) + c->data_len +
    sizeof (c->checksum);

  crc_len = total_len - sizeof (c->command) - sizeof (c->checksum);

  crc_offset = total_len - sizeof (c->checksum);

  c->count = total_len - sizeof (c->command);

  data = (uint8_t*)malloc (total_len);

  assert (NULL != data);

  lca_print_command (c);

  LCA_LOG (DEBUG,
           "Total len: %d, count: %d, CRC_LEN: %d, CRC_OFFSET: %d\n",
           total_len, c->count, crc_len, crc_offset);

  /* copy over the command */
  data[0] = c->command;
  data[1] = c->count;
  data[2] = c->opcode;
  data[3] = c->param1;
  data[4] = c->param2[0];
  data[5] = c->param2[1];
  if (c->data_len > 0)
    memcpy (&data[6], c->data, c->data_len);

  crc = (uint16_t *)&data[crc_offset];
  *crc = lca_calculate_crc16 (&data[1], crc_len);

  *serialized = data;

#else
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
#endif

  return total_len;

}

enum LCA_STATUS_RESPONSE
lca_read_and_validate (int fd, uint8_t *buf, unsigned int len)
{

  uint8_t* tmp = NULL;
  const int PAYLOAD_LEN_SIZE = 1;
  const int CRC_SIZE = 2;
  enum LCA_STATUS_RESPONSE status = RSP_COMM_ERROR;
  int recv_buf_len = 0;
  bool crc_valid;
  unsigned int crc_offset;
  int read_bytes;
  const unsigned int STATUS_RSP = 4;

  assert (NULL != buf);

  recv_buf_len = len + PAYLOAD_LEN_SIZE + CRC_SIZE;

  crc_offset = recv_buf_len - 2;

  /* The buffer that comes back has a length byte at the front and a
   * two byte crc at the end. */
  tmp = lca_malloc_wipe (recv_buf_len);

  read_bytes = lca_read (fd, tmp, recv_buf_len);

  /* First Case: We've read the buffer and it's a status packet */

  if (read_bytes == recv_buf_len && tmp[0] == STATUS_RSP)
  {
      lca_print_hex_string ("Status RSP", tmp, STATUS_RSP);
      status = lca_get_status_response (tmp);
      LCA_LOG (DEBUG, status_to_string (status));
      LCA_LOG (DEBUG, "Copying %d into buf", tmp[1]);
      memcpy (buf, &tmp[1], 1);

  }

  /* Second case: We received the expected message length */
  else if (read_bytes == recv_buf_len && tmp[0] == recv_buf_len)
    {
      lca_print_hex_string ("Received RSP", tmp, recv_buf_len);

      crc_valid = lca_is_crc_16_valid (tmp,
                                        recv_buf_len - LCA_CRC_16_LEN,
                                        tmp + crc_offset);

      if (true == crc_valid)
        {
          lca_wipe (buf, len);
          memcpy (buf, &tmp[1], len);
          status = RSP_SUCCESS;

        }
      else
        {
          perror ("CRC FAIL!\n");
        }
    }
  else
    {
      LCA_LOG (DEBUG,"Read failed, retrying");
      status = RSP_NAK;

    }

  lca_free_wipe (tmp, recv_buf_len);

  return status;
}

static struct lca_octet_buffer
lca_get_response (int fd, const int MAX_RECV_LEN, struct timespec wait_time)
{

  const int STATUS_RSP_LEN = 4;
  struct lca_octet_buffer tmp = lca_make_buffer (STATUS_RSP_LEN);
  struct lca_octet_buffer rsp = {0,0};

  int read_bytes = 0;;

  /* The buffer that comes back has a length byte at the front and a
   * two byte crc at the end. */
  read_bytes = lca_read_sleep (fd, tmp.ptr, tmp.len, wait_time);

  /* First Case: We've read the buffer and it's a status packet */

  if (read_bytes == STATUS_RSP_LEN && tmp.ptr[0] == STATUS_RSP_LEN)
    {
      lca_print_hex_string ("Status RSP", tmp.ptr, STATUS_RSP_LEN);
      enum LCA_STATUS_RESPONSE status = RSP_COMM_ERROR;
      status = lca_get_status_response (tmp.ptr);
      LCA_LOG (DEBUG, status_to_string (status));

      rsp = tmp;
    }
  /* Second Case: There is more to read */
  else if (read_bytes > 0 &&
           tmp.ptr[0] > STATUS_RSP_LEN &&
           tmp.ptr[0] <= MAX_RECV_LEN)
    {
      const int PACKET_SIZE = tmp.ptr[0];
      rsp = lca_make_buffer (PACKET_SIZE);
      read_bytes = lca_read (fd, rsp.ptr + STATUS_RSP_LEN, PACKET_SIZE);
      if (read_bytes + STATUS_RSP_LEN == PACKET_SIZE)
        {
          memcpy (rsp.ptr, tmp.ptr, STATUS_RSP_LEN);
          lca_free_octet_buffer (tmp);
        }
      else
        {
          LCA_LOG (DEBUG, "Error reading rest of response.");
        }
    }
  /* Otherwise: Error */
  else
    {
      LCA_LOG (DEBUG, "Read failed.");
    }

  /* Data is read, check the CRC before returning */
  if (NULL != rsp.ptr && rsp.len > LCA_CRC_16_LEN)
    {
      if (lca_is_crc_16_valid (rsp.ptr,
                                rsp.len - LCA_CRC_16_LEN,
                                rsp.ptr - LCA_CRC_16_LEN))
        {
          LCA_LOG (DEBUG, "Received CRC checks out.");
          /* Strip off length byte and CRC and return just the data */
          struct lca_octet_buffer data =
            lca_make_buffer (rsp.len - LCA_CRC_16_LEN - 1);

          memcpy (data.ptr, rsp.ptr + 1, data.len);
          lca_free_octet_buffer (rsp);
          rsp = data;
        }
      else
        {
          LCA_LOG (DEBUG, "Received CRC Failed!");
          lca_free_octet_buffer (rsp);
        }
    }
  else if (NULL != rsp.ptr && rsp.len <= LCA_CRC_16_LEN)
    {
      LCA_LOG (DEBUG, "Message does not have a CRC");
      lca_free_octet_buffer (rsp);
    }

  return rsp;
}


struct lca_octet_buffer
lca_send_and_get_rsp (int fd,
                       const uint8_t *send_buf,
                       const unsigned int send_buf_len,
                       struct timespec wait_time,
                       const int MAX_RECV_LEN)
{
  ssize_t result = 0;
  struct lca_octet_buffer rsp = {0,0};

  assert (NULL != send_buf);

  if (1 < (result = lca_write (fd, send_buf, send_buf_len)))
    {
      rsp = lca_get_response (fd, MAX_RECV_LEN, wait_time);
    }
  else
    {
      LCA_LOG (DEBUG, "Send failed.");
    }

  return rsp;
}
