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

#include <assert.h>
#include <gcrypt.h>
#include "../libcryptoauth.h"
#include "hash.h"

/*
 *  hkdfExtract
 *
 *  Description:
 *      This function will perform HKDF extraction.
 *
 *  Parameters:
 *      whichSha: [in]
 *          One of SHA1, SHA224, SHA256, SHA384, SHA512
 *      salt[ ]: [in]
 *          The optional salt value (a non-secret random value);
 *          if not provided (salt == NULL), it is set internally
 *          to a string of HashLen(whichSha) zeros.
 *      salt_len: [in]
 *          The length of the salt value.  (Ignored if salt == NULL.)
 *      ikm[ ]: [in]
 *          Input keying material.
 *      ikm_len: [in]
 *          The length of the input keying material.
 *      prk[ ]: [out]
 *          Array where the HKDF extraction is to be stored.
 *          Must be larger than USHAHashSize(whichSha);
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int
hkdf_256_extract( const uint8_t *salt, int salt_len,
                  const uint8_t *ikm, int ikm_len,
                  uint8_t prk[LCA_SHA256_DLEN])
{
  unsigned char nullSalt[LCA_SHA256_DLEN];
  struct lca_octet_buffer saltb, keyb, prkb;

  assert (salt >= 0);
  assert (salt);
  assert (ikm);
  assert (prk);

  if (salt == 0)
    {
      salt = nullSalt;
      salt_len = LCA_SHA256_DLEN;
      memset(nullSalt, '\0', salt_len);
    }

  saltb.ptr = salt;
  saltb.len = salt_len;

  keyb.ptr = ikm;
  keyb.len = ikm_len;

  prkb = hmac_buffer (keyb, saltb);

  if (NULL == prkb.ptr)
    return -1;
  else
    {
      memcpy (prk, prkb.ptr, prkb.len);
      lca_free_octet_buffer(prkb);
    }

  return 0;
}
