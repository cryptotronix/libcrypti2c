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

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>
#include "../libcryptoauth.h"

static enum LCA_LOG_LEVEL CURRENT_LOG_LEVEL = INFO;

void
LCA_LOG(enum LCA_LOG_LEVEL lvl, const char *format, ...)
{
  if (lvl <= CURRENT_LOG_LEVEL)
    {
      va_list args;
      va_start(args, format);
      vfprintf(stdout, format, args);
      printf("\n");
      va_end(args);
    }
}

void
lca_set_log_level(enum LCA_LOG_LEVEL lvl)
{
  CURRENT_LOG_LEVEL = lvl;

}

void
lca_print_hex_string(const char *str, const uint8_t *hex, unsigned int len)
{

  if (CURRENT_LOG_LEVEL < DEBUG)
    return;

  unsigned int i;

  assert(NULL != str);
  assert(NULL != hex);

  printf("%s : ", str);

  for (i = 0; i < len; i++)
    {
      if (i > 0) printf(" ");
      printf("0x%02X", hex[i]);
    }

  printf("\n");

}

bool
lca_is_debug (void)
{
  return (DEBUG == CURRENT_LOG_LEVEL) ? true : false;
}
