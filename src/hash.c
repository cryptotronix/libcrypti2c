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
#include "hash.h"

struct lca_octet_buffer
lca_sha256 (FILE *fp)
{

  struct lca_octet_buffer digest;

  assert (NULL != fp);
  /* Init gcrypt */
  assert (NULL != gcry_check_version (NULL));

  struct gcry_md_handle *hd;
  struct gcry_md_handle **hd_ptr = &hd;

  assert (GPG_ERR_NO_ERROR == gcry_md_open (hd_ptr, GCRY_MD_SHA256, 0));

  int c;

  printf ("before hash: \n");
  /* Perform the hash */
  while ((c = getc (fp)) != EOF)
    {
      printf("0x%02X ", c);
      gcry_md_putc (hd, c);
    }
  printf ("\nafter hash \n");

  unsigned char *result;

  assert ((result = gcry_md_read (hd, GCRY_MD_SHA256)) != NULL);

  /* copy over to the digest */
  const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
  digest = lca_make_buffer (DLEN);
  memcpy (digest.ptr, result, DLEN);

  gcry_md_close (hd);

  return digest;
}

int
lca_hash_file (FILE *fp, gcry_sexp_t *digest)
{
  assert (NULL != fp);
  assert (NULL != digest);

  struct lca_octet_buffer result;
  int rc = -1;

  result = lca_sha256 (fp);

  if (NULL == result.ptr)
    return -2;

  rc = gcry_sexp_build (digest, NULL,
                        "(data (flags raw)\n"
                        " (value %b))",
                        result.len, result.ptr);

  free (result.ptr);

  return rc;

}

struct lca_octet_buffer
lca_sha256_buffer (struct lca_octet_buffer data)
  {
    struct lca_octet_buffer digest;
    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);

    assert (NULL != data.ptr);
    /* Init gcrypt */
    assert (NULL != gcry_check_version (NULL));

    digest = lca_make_buffer (DLEN);

    gcry_md_hash_buffer (GCRY_MD_SHA256, digest.ptr, data.ptr, data.len);

    return digest;
  }

unsigned int
copy_over (uint8_t *dst, const uint8_t *src, unsigned int src_len,
          unsigned int offset)
{
  memcpy(dst + offset, src, src_len);
  return offset + src_len;
}


struct lca_octet_buffer
perform_hash(struct lca_octet_buffer challenge,
             struct lca_octet_buffer key,
             uint8_t mode, uint16_t param2,
             struct lca_octet_buffer otp8,
             struct lca_octet_buffer otp3,
             struct lca_octet_buffer sn4,
             struct lca_octet_buffer sn23)
{

  assert (NULL != challenge.ptr); assert (32 == challenge.len);
  assert (NULL != key.ptr); assert (32 == key.len);
  assert (NULL != otp8.ptr); assert (8 == otp8.len);
  assert (NULL != otp3.ptr); assert (3 == otp3.len);
  assert (NULL != sn4.ptr); assert (4 == sn4.len);
  assert (NULL != sn23.ptr); assert (2 == sn23.len);

  const uint8_t opcode = {0x08};
  const uint8_t sn = 0xEE;
  const uint8_t sn2[] ={0x01, 0x23};

  unsigned int len = challenge.len + key.len + sizeof(opcode) + sizeof(mode)
    + sizeof(param2) + otp8.len + otp3.len + sizeof(sn)  + sn4.len
    + sizeof(sn2) + sn23.len;

  uint8_t *buf = lca_malloc_wipe(len);

  unsigned int offset = 0;
  offset = copy_over (buf, key.ptr, key.len, offset);
  offset = copy_over (buf, challenge.ptr, challenge.len, offset);
  offset = copy_over (buf, &opcode, sizeof(opcode), offset);
  offset = copy_over (buf, &mode, sizeof(mode), offset);
  offset = copy_over (buf, (uint8_t *)&param2, sizeof(param2), offset);
  offset = copy_over (buf, otp8.ptr, otp8.len, offset);
  offset = copy_over (buf, otp3.ptr, otp3.len, offset);
  offset = copy_over (buf, &sn, sizeof(sn), offset);
  offset = copy_over (buf, sn4.ptr, sn4.len, offset);
  offset = copy_over (buf, sn2, sizeof (sn2), offset);
  offset = copy_over (buf, sn23.ptr, sn23.len, offset);

  lca_print_hex_string("Data to hash", buf, len);
  struct lca_octet_buffer data_to_hash = {buf, len};
  struct lca_octet_buffer digest;
  digest = lca_sha256_buffer (data_to_hash);

  lca_print_hex_string ("Result hash", digest.ptr, digest.len);

  free(buf);

  return digest;
}

bool
lca_verify_hash_defaults (struct lca_octet_buffer challenge,
                           struct lca_octet_buffer challenge_rsp,
                           struct lca_octet_buffer key, unsigned int key_slot)
{

  bool result = false;

  const uint8_t MAX_NUM_DATA_SLOTS = 16;

  struct lca_octet_buffer otp8 = lca_make_buffer (8);
  struct lca_octet_buffer otp3 = lca_make_buffer (3);
  struct lca_octet_buffer sn4 = lca_make_buffer (4);
  struct lca_octet_buffer sn23 = lca_make_buffer (2);
  uint8_t mode = 0;
  uint16_t param2 = 0;

  uint8_t *p = (uint8_t *)&param2;
  assert (key_slot < MAX_NUM_DATA_SLOTS);
  *p = key_slot;


  struct lca_octet_buffer digest;
  digest = perform_hash (challenge, key, mode, param2, otp8, otp3, sn4, sn23);

  lca_free_octet_buffer (otp8);
  lca_free_octet_buffer (otp3);
  lca_free_octet_buffer (sn4);
  lca_free_octet_buffer (sn23);

  result = lca_memcmp_octet_buffer (digest, challenge_rsp);

  lca_free_octet_buffer (digest);

  return result;

}

struct lca_octet_buffer hmac_buffer (struct lca_octet_buffer data_to_hash,
                                 struct lca_octet_buffer key)
{
  struct lca_octet_buffer digest;
  const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);

  assert (NULL != data_to_hash.ptr);
  assert (NULL != key.ptr);

  /* Init gcrypt */
  assert (NULL != gcry_check_version (NULL));

  digest = lca_make_buffer (DLEN);

  gcry_md_hd_t hd;

  gcry_md_open (&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);

  assert (NULL != hd);

  gcry_md_setkey (hd, key.ptr, key.len);

  gcry_md_write (hd, data_to_hash.ptr, data_to_hash.len);

  unsigned char *result = gcry_md_read (hd, GCRY_MD_SHA256);

  assert (NULL != result);

  memcpy (digest.ptr, result, DLEN);

  gcry_md_close (hd);

  return digest;
}

struct lca_octet_buffer
prepare_hmac_buffer(struct lca_octet_buffer challenge,
                    struct lca_octet_buffer key,
                    uint8_t mode,
                    uint8_t key_slot,
                    struct lca_octet_buffer otp8,
                    struct lca_octet_buffer otp3,
                    struct lca_octet_buffer sn4,
                    struct lca_octet_buffer sn23)
{
  assert (NULL != challenge.ptr); assert (32 == challenge.len);
  assert (NULL != key.ptr); assert (32 == key.len);
  assert (NULL != otp8.ptr); assert (8 == otp8.len);
  assert (NULL != otp3.ptr); assert (3 == otp3.len);
  assert (NULL != sn4.ptr); assert (4 == sn4.len);
  assert (NULL != sn23.ptr); assert (2 == sn23.len);

  const uint8_t MAX_NUM_DATA_SLOTS = 16;
  uint16_t param2 = 0;

  uint8_t *p = (uint8_t *)&param2;
  assert (key_slot < MAX_NUM_DATA_SLOTS);
  *p = key_slot;

  struct lca_octet_buffer zeros = lca_make_buffer (32);

  const uint8_t opcode = {0x11};
  const uint8_t sn = 0xEE;
  const uint8_t sn2[] ={0x01, 0x23};

  unsigned int len = zeros.len +
    challenge.len +
    sizeof(opcode) +
    sizeof(mode) +
    sizeof(param2) +
    otp8.len +
    otp3.len +
    sizeof(sn) +
    sn4.len +
    sizeof(sn2) +
    sn23.len;

  assert (88 == len);

  uint8_t *buf = lca_malloc_wipe(len);

  unsigned int offset = 0;
  offset = copy_over(buf, zeros.ptr, zeros.len, offset);
  offset = copy_over(buf, challenge.ptr, challenge.len, offset);
  offset = copy_over(buf, &opcode, sizeof(opcode), offset);
  offset = copy_over(buf, &mode, sizeof(mode), offset);
  offset = copy_over(buf, (uint8_t *)&param2, sizeof(param2), offset);
  offset = copy_over(buf, otp8.ptr, otp8.len, offset);
  offset = copy_over(buf, otp3.ptr, otp3.len, offset);
  offset = copy_over(buf, &sn, sizeof(sn), offset);
  offset = copy_over(buf, sn4.ptr, sn4.len, offset);
  offset = copy_over(buf, sn2, sizeof (sn2), offset);
  offset = copy_over(buf, sn23.ptr, sn23.len, offset);

  lca_print_hex_string("Data to hmac", buf, len);

  struct lca_octet_buffer result = {buf, len};

  return result;
}

struct lca_octet_buffer
perform_hmac_256(struct lca_octet_buffer challenge,
                 struct lca_octet_buffer key,
                 uint8_t mode,
                 uint8_t key_slot,
                 struct lca_octet_buffer otp8,
                 struct lca_octet_buffer otp3,
                 struct lca_octet_buffer sn4,
                 struct lca_octet_buffer sn23)
{

  struct lca_octet_buffer data_to_hmac =
    prepare_hmac_buffer(challenge, key, mode, key_slot,
                        otp8, otp3, sn4, sn23);

  struct lca_octet_buffer digest;
  digest = hmac_buffer (data_to_hmac, key);

  lca_print_hex_string("Result hash", digest.ptr, digest.len);

  lca_free_octet_buffer(data_to_hmac);

  return digest;
}

struct lca_octet_buffer
lca_soft_hmac256_defaults(struct lca_octet_buffer challenge,
                          struct lca_octet_buffer key,
                          uint8_t key_slot)
{
  struct lca_octet_buffer otp8 = lca_make_buffer (8);
  struct lca_octet_buffer otp3 = lca_make_buffer (3);
  struct lca_octet_buffer sn4 = lca_make_buffer (4);
  struct lca_octet_buffer sn23 = lca_make_buffer (2);
  uint8_t mode = 0x04;

  struct lca_octet_buffer digest;
  digest = perform_hmac_256 (challenge, key, mode, key_slot,
                             otp8, otp3, sn4, sn23);

  lca_free_octet_buffer (otp8);
  lca_free_octet_buffer (otp3);
  lca_free_octet_buffer (sn4);
  lca_free_octet_buffer (sn23);

  return digest;

}

bool
lca_verify_hmac_defaults (struct lca_octet_buffer challenge,
                           struct lca_octet_buffer challenge_rsp,
                           struct lca_octet_buffer key, unsigned int key_slot)
{

  bool result = false;
  const uint8_t MAX_NUM_DATA_SLOTS = 16;

  struct lca_octet_buffer otp8 = lca_make_buffer (8);
  struct lca_octet_buffer otp3 = lca_make_buffer (3);
  struct lca_octet_buffer sn4 = lca_make_buffer (4);
  struct lca_octet_buffer sn23 = lca_make_buffer (2);
  uint8_t mode = 0x04;

  struct lca_octet_buffer digest;
  digest = perform_hmac_256 (challenge, key, mode, key_slot,
                             otp8, otp3, sn4, sn23);

  lca_free_octet_buffer (otp8);
  lca_free_octet_buffer (otp3);
  lca_free_octet_buffer (sn4);
  lca_free_octet_buffer (sn23);

  result = lca_memcmp_octet_buffer (digest, challenge_rsp);

  lca_free_octet_buffer (digest);

  return result;

}
