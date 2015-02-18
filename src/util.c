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

#include "util.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include <ctype.h>
#include <limits.h>

void
lca_wipe(unsigned char *buf, unsigned int len)
{

  assert(NULL != buf);
  memset(buf, 0, len);
}

uint8_t*
lca_malloc_wipe(unsigned int len)
{
  uint8_t* buf = malloc(len);

  assert(NULL != buf);

  lca_wipe(buf, len);

  return buf;

}

void
lca_free_wipe(unsigned char* buf, unsigned int len)
{
  lca_wipe(buf, len);

  free(buf);
}

uint8_t
lca_reverse_bits_in_byte(uint8_t b)
{
  /* This gem is from
     http://graphics.stanford.edu/~seander/bithacks.html
  */
  return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;

}

struct lca_octet_buffer
lca_make_buffer(unsigned int len)
{
  struct lca_octet_buffer b = {0,0};
  b.len = len;
  b.ptr = lca_malloc_wipe(len);

  return b;
}


void
lca_free_octet_buffer(struct lca_octet_buffer buf)
{
    lca_free_wipe(buf.ptr, buf.len);


}

bool
lca_memcmp_octet_buffer (struct lca_octet_buffer lhs,
                          struct lca_octet_buffer rhs)
{
  assert (NULL != lhs.ptr); assert (NULL != rhs.ptr);

  bool result = false;

  if (lhs.len == rhs.len)
    if (0 == memcmp (lhs.ptr, rhs.ptr, lhs.len))
      result = true;

  return result;

}

unsigned int
lca_c2b (char c)
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

struct lca_octet_buffer
lca_ascii_hex_2_bin (const char* hex,
                      unsigned int max_len)
{
  struct lca_octet_buffer result = {0,0};

  assert (NULL != hex);

  if (0 == memcmp("0x", hex, 2))
    hex +=2;

  unsigned int len = strnlen (hex, max_len);

  if (len % 2 == 0)
    {
      result = lca_make_buffer (len / 2);

      unsigned int x;

      bool ishex = true;
      for (x=0; x<len && ishex; x++)
        {
          unsigned int a;

          if ((a = lca_c2b (hex[x])) != UINT_MAX)
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
          lca_free_octet_buffer (result);
          result.ptr = NULL;
        }
    }


  return result;
}

bool
lca_is_all_hex (const char* hex, unsigned int max_len)
{
  struct lca_octet_buffer bin = lca_ascii_hex_2_bin (hex, max_len);
  bool ishex = false;

  if (NULL != bin.ptr)
    {
      ishex = true;
      lca_free_octet_buffer (bin);
    }

  return ishex;
}

unsigned int
lca_copy_buffer (struct lca_octet_buffer dst, unsigned int offset,
                  const struct lca_octet_buffer src)
{

  return lca_copy_to_buffer (dst, offset, src.ptr, src.len);

}


unsigned int
lca_copy_to_buffer (struct lca_octet_buffer buf, unsigned int offset,
                     const uint8_t *p, unsigned int len)
{

  assert (NULL != p);
  assert (buf.ptr != NULL);

  assert (len <= buf.len + offset);

  memcpy (buf.ptr + offset, p, len);

  return offset + len;

}


struct lca_octet_buffer
lca_xor_buffers (const struct lca_octet_buffer lhs,
                  const struct lca_octet_buffer rhs)
{

  assert (NULL != lhs.ptr && NULL != rhs.ptr);
  assert (0 != rhs.len && lhs.len == rhs.len);

  unsigned int x = 0;

  struct lca_octet_buffer buf = lca_make_buffer (rhs.len);

  for (x=0; x < rhs.len; x++)
    {
      buf.ptr[x] = lhs.ptr[x] ^ rhs.ptr[x];
    }

  lca_print_hex_string ("XOR", buf.ptr, buf.len);

  return buf;

}
