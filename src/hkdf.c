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
lca_hkdf_256_extract( const uint8_t *salt, int salt_len,
                      const uint8_t *ikm, int ikm_len,
                      uint8_t prk[LCA_SHA256_DLEN])
{
  unsigned char nullSalt[LCA_SHA256_DLEN];
  struct lca_octet_buffer saltb, keyb, prkb;

  assert (salt >= 0);
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


int
lca_hkdf_256_expand(const uint8_t prk[ ], int prk_len,
                    const unsigned char *info, int info_len,
                    uint8_t okm[ ], int okm_len)
{
  int hash_len, N;
  unsigned char T[LCA_SHA256_DLEN];
  int Tlen, where, i;

  if (info == 0)
    {
      info = (const unsigned char *)"";
      info_len = 0;
    }

  assert (info > 0);

  assert (okm_len > 0);
  assert (okm);

  hash_len = LCA_SHA256_DLEN;
  if (prk_len < hash_len)
    return -2;
  N = okm_len / hash_len;
  if ((okm_len % hash_len) != 0) N++;
  if (N > 255)
    return -3;

  /* setup hmac with gcrypt */
  gcry_md_hd_t hd;
  gcry_md_open (&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);

  assert (NULL != hd);
  gcry_md_setkey (hd, prk, prk_len);

  Tlen = 0;
  where = 0;
  for (i = 1; i <= N; i++)
    {
      unsigned char c = i;
      gcry_md_reset(hd);

      gcry_md_write (hd, T, Tlen);
      gcry_md_write (hd, info, info_len);
      gcry_md_write (hd, &c, 1);

      unsigned char *result = gcry_md_read (hd, GCRY_MD_SHA256);

      if (result == NULL)
        return -4;
      memcpy (T, result, hash_len);
      memcpy(okm + where, T,
             (i != N) ? hash_len : (okm_len - where));
      where += hash_len;
      Tlen = hash_len;
    }

  gcry_md_close (hd);

  return 0;
}


int
lca_hkdf(const unsigned char *salt, int salt_len,
         const unsigned char *ikm, int ikm_len,
         const unsigned char *info, int info_len,
         uint8_t okm[ ], int okm_len)
{
  uint8_t prk[LCA_SHA256_DLEN];
  return lca_hkdf_256_extract(salt, salt_len, ikm, ikm_len, prk) ||
         lca_hkdf_256_expand(prk, LCA_SHA256_DLEN, info,
                             info_len, okm, okm_len);
}
