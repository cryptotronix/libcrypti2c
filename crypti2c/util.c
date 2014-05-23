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

#include "util.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include <ctype.h>
#include <limits.h>

void
ci2c_wipe(unsigned char *buf, unsigned int len)
{

  assert(NULL != buf);
  memset(buf, 0, len);
}

uint8_t*
ci2c_malloc_wipe(unsigned int len)
{
  uint8_t* buf = malloc(len);

  assert(NULL != buf);

  ci2c_wipe(buf, len);

  return buf;

}

void
ci2c_free_wipe(unsigned char* buf, unsigned int len)
{
  ci2c_wipe(buf, len);

  free(buf);
}

uint8_t
ci2c_reverse_bits_in_byte(uint8_t b)
{
  /* This gem is from
     http://graphics.stanford.edu/~seander/bithacks.html
  */
  return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;

}

struct ci2c_octet_buffer
ci2c_make_buffer(unsigned int len)
{
    struct ci2c_octet_buffer b = {};
    b.len = len;
    b.ptr = ci2c_malloc_wipe(len);

    return b;
}


void
ci2c_free_octet_buffer(struct ci2c_octet_buffer buf)
{
    ci2c_free_wipe(buf.ptr, buf.len);


}

bool
ci2c_memcmp_octet_buffer (struct ci2c_octet_buffer lhs,
                          struct ci2c_octet_buffer rhs)
{
  assert (NULL != lhs.ptr); assert (NULL != rhs.ptr);

  bool result = false;

  if (lhs.len == rhs.len)
    if (0 == memcmp (lhs.ptr, rhs.ptr, lhs.len))
      result = true;

  return result;

}

unsigned int
ci2c_c2b (char c)
{
  unsigned int result = 0;

  if (c >= '0' && c <= '9')
    result = c - '0';
  else if (c >= 'A' && c <= 'F')
    result = c - 'A' + 10;
  else if (c >= 'a' && c >= 'f')
    result = c - 'a' + 10;
  else
    result = UINT_MAX;

  return result;

}

struct ci2c_octet_buffer
ci2c_ascii_hex_2_bin (const char* hex,
                      unsigned int max_len)
{
  struct ci2c_octet_buffer result = {0,0};

  assert (NULL != hex);

  if (0 == memcmp("0x", hex, 2))
    hex +=2;

  unsigned int len = strnlen (hex, max_len);

  if (len % 2 == 0)
    {
      result = ci2c_make_buffer (len / 2);

      int x;

      bool ishex = true;
      for (x=0; x<len && ishex; x++)
        {
          unsigned int a;

          if ((a = ci2c_c2b (hex[x])) != UINT_MAX)
            {
              if (x % 2 == 0)
                result.ptr[x/2] = (a << 4);
              else
                result.ptr[x/2] += a;
            }
          else
            ishex = false;

        }

      if (!ishex)
        {
          ci2c_free_octet_buffer (result);
          result.ptr = NULL;
        }
    }


  return result;
}

bool
ci2c_is_all_hex (const char* hex, unsigned int max_len)
{
  struct ci2c_octet_buffer bin = ci2c_ascii_hex_2_bin (hex, max_len);
  bool ishex = false;

  if (NULL != bin.ptr)
    {
      ishex = true;
      ci2c_free_octet_buffer (bin);
    }

  return ishex;
}

unsigned int
ci2c_copy_buffer (struct ci2c_octet_buffer dst, unsigned int offset,
                  const struct ci2c_octet_buffer src)
{

  return ci2c_copy_to_buffer (dst, offset, src.ptr, src.len);

}


unsigned int
ci2c_copy_to_buffer (struct ci2c_octet_buffer buf, unsigned int offset,
                     const uint8_t *p, unsigned int len)
{

  assert (NULL != p);
  assert (buf.ptr != NULL);

  assert (len <= buf.len + offset);

  memcpy (buf.ptr + offset, p, len);

  return offset + len;

}


struct ci2c_octet_buffer
ci2c_xor_buffers (const struct ci2c_octet_buffer lhs,
                  const struct ci2c_octet_buffer rhs)
{

  assert (NULL != lhs.ptr && NULL != rhs.ptr);
  assert (0 != rhs.len && lhs.len == rhs.len);

  int x = 0;

  struct ci2c_octet_buffer buf = ci2c_make_buffer (rhs.len);

  for (x=0; x < rhs.len; x++)
    {
      buf.ptr[x] = lhs.ptr[x] ^ rhs.ptr[x];
    }

  ci2c_print_hex_string ("XOR", buf.ptr, buf.len);

  return buf;

}
