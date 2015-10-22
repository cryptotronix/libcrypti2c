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
#include <yacl.h>
#include "../libcryptoauth.h"
#include <stdint.h>
#include <string.h>

#ifdef CRYPTOAUTH_HAVE_GCRYPT
void
lca_print_sexp (gcry_sexp_t to_print) {

  if (!lca_is_debug())
    return;

  const int DEBUG_MAX_SIZE = 2048;
  char * debug = malloc (DEBUG_MAX_SIZE);
  memset (debug, 0, DEBUG_MAX_SIZE);
  int bytes = gcry_sexp_sprint (to_print,
                                GCRYSEXP_FMT_ADVANCED,
                                debug,
                                DEBUG_MAX_SIZE);
  LCA_LOG (DEBUG, "%d %s", bytes, debug);
  free (debug);
}

bool
lca_ecdsa_p256_verify (struct lca_octet_buffer pub_key,
                        struct lca_octet_buffer signature,
                        struct lca_octet_buffer sha256_digest)
{
  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  if (lca_is_debug())
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

  assert (65 == pub_key.len); /* +1 for uncompressed point tag */
  assert (64 == signature.len);
  assert (32 == sha256_digest.len);

  LCA_LOG (DEBUG, "Gcrypt init");

  gcry_sexp_t g_pub_key;
  gcry_sexp_t g_digest;
  gcry_sexp_t g_sig;
  int rc = 0;

  rc = gcry_sexp_build (&g_pub_key, NULL,
                        "(public-key\n"
                        " (ecdsa\n"
                        "  (curve \"NIST P-256\")\n"
                        "  (q %b)"
                        "))", pub_key.len, pub_key);

  lca_print_sexp (g_pub_key);

  assert (0 == rc);

  rc = gcry_sexp_build (&g_digest, NULL,
                        "(data (flags raw)\n"
                        " (value %b))",
                        sha256_digest.len, sha256_digest.ptr);

  assert (0 == rc);

  lca_print_sexp (g_digest);

  rc = gcry_sexp_build (&g_sig, NULL,
                        "(sig-val(ecdsa(r %b)(s %b)))",
                        32, signature.ptr,
                        32, signature.ptr + 32);

  assert (0 == rc);

  lca_print_sexp( g_sig );

  rc = gcry_pk_verify (g_sig, g_digest, g_pub_key);
  LCA_LOG (DEBUG, "verify complete");
  if (0 != rc)
    LCA_LOG (DEBUG, "gcry_pk_verify failed: %s", gpg_strerror (rc));
  else
    LCA_LOG (DEBUG, "gcry_pk_verify success");

  gcry_sexp_release (g_sig);
  gcry_sexp_release (g_digest);
  gcry_sexp_release (g_pub_key);

  return (rc == 0) ? true : false;
}



struct lca_octet_buffer
lca_add_uncompressed_point_tag (struct lca_octet_buffer q)
{
  assert (NULL != q.ptr);
  assert (64 == q.len); /* only support P256 now */

  struct lca_octet_buffer new_q = lca_make_buffer (65);

  new_q.ptr[0] = 0x04;

  memcpy (new_q.ptr + 1, q.ptr, q.len);

  lca_free_octet_buffer (q);

  return new_q;

}

int
lca_gen_soft_keypair (gcry_sexp_t *key)
{
  static const char key_param[]=
    "(genkey\n"
    "(ecdsa\n"
    "(curve \"NIST P-256\")\n"
    "(flags param)))";

  assert (NULL != key);

  gcry_sexp_t keyparam;
  int rc;

  rc = gcry_sexp_build (&keyparam, NULL, key_param);


  lca_print_sexp (keyparam);

  if (0 == rc)
    {
      rc = gcry_pk_genkey (key, keyparam);
      if (rc)
        {
          LCA_LOG (DEBUG, "gcry_pk_genkey failed: %s", gpg_strerror (rc));
        }
      else
        {
          lca_print_sexp (*key);
        }

      gcry_sexp_release (keyparam);
    }

  return rc;

}

int
lca_ssig2buffer (const gcry_sexp_t *sig, struct lca_octet_buffer *r_out,
                 struct lca_octet_buffer *s_out)
{
  assert (NULL != sig);

  gcry_error_t  rc = -1;
  gcry_sexp_t sexp_r, sexp_s;
  gcry_mpi_t mpi_r, mpi_s;
  unsigned char *raw_r, *raw_s;
  size_t size_r, size_s;


  if (NULL == (sexp_r = gcry_sexp_find_token(*sig, "r", 0)))
    goto OUT;

  if (NULL == (sexp_s = gcry_sexp_find_token(*sig, "s", 0)))
    goto FREE_R;

  lca_print_sexp (*sig);

  if (NULL == (mpi_r = gcry_sexp_nth_mpi (sexp_r, 1, GCRYMPI_FMT_USG)))
    goto FREE_S;

  if (NULL == (mpi_s = gcry_sexp_nth_mpi (sexp_s, 1, GCRYMPI_FMT_USG)))
    goto FREE_MPI_R;

  rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_r, &size_r, mpi_r);
  if (rc)
    goto FREE_MPI_S;

  rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_s, &size_s, mpi_s);
  if (rc)
    goto FREE_RAW_R;

  *r_out = lca_make_buffer(size_r);
  memcpy (r_out->ptr, raw_r, size_r);
  r_out->len = size_r;

  *s_out = lca_make_buffer(size_s);
  memcpy (s_out->ptr, raw_s, size_s);
  s_out->len = size_s;

  rc = 0;

  unsigned char *pc, *xp;
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pc, NULL, mpi_r);
  gcry_mpi_aprint(GCRYMPI_FMT_HEX, &xp, NULL, mpi_s);

  lca_print_hex_string("R: ", r_out->ptr, r_out->len);
  lca_print_hex_string("S: ", s_out->ptr, s_out->len);

  gcry_free (raw_s);
 FREE_RAW_R:
  gcry_free (raw_r);
 FREE_MPI_S:
  gcry_mpi_release (mpi_s);
 FREE_MPI_R:
  gcry_mpi_release (mpi_r);
 FREE_S:
  gcry_sexp_release (sexp_s);
 FREE_R:
  gcry_sexp_release (sexp_r);
 OUT:
  return rc;
}

struct lca_octet_buffer
lca_sig2buf (const gcry_sexp_t *sig)
{
  int rc = -1;
  struct lca_octet_buffer r, s, result = {0,0};
  int slen;

  rc = lca_ssig2buffer (sig, &r, &s);
  if (rc)
    return result;

  assert (NULL != r.ptr);
  assert (NULL != s.ptr);

  slen = r.len + s.len;

  result = lca_make_buffer (slen);

  memcpy (result.ptr, r.ptr, r.len);
  memcpy (result.ptr + r.len, s.ptr, s.len);

  lca_free_octet_buffer(r);
  lca_free_octet_buffer(s);

  return result;

}

int
lca_soft_sign (gcry_sexp_t *key_pair, struct lca_octet_buffer hash,
               gcry_sexp_t *sig_out)
{
  gcry_sexp_t digest;
  gpg_error_t err;

  assert (NULL != key_pair);


  static const char zzz[] =
    "(data (flags raw)\n"
    " (value %b))";

  lca_set_log_level(DEBUG);
  //  lca_print_sexp (key);
  lca_print_sexp (*key_pair);

  if ((err = gcry_sexp_build (&digest, NULL, zzz, hash.len, hash.ptr)))
    {
      printf ("line %d: %s", __LINE__, gpg_strerror (err));
      return err;
    }

  /* if ((err = gcry_sexp_new (&digest, my_string, 0, 1))) */
  /*   { */
  /*     printf ("line %d: %s", __LINE__, gpg_strerror (err)); */
  /*     return err; */
  /*   } */

  if ((err = gcry_pk_sign (sig_out, digest, *key_pair)))
    {
      printf ("line %d: %s", __LINE__, gpg_strerror (err));
      return err;
    }

  return 0;

}


int
lca_load_signing_key (const char *keyfile, gcry_sexp_t *key)
{
  assert (NULL != keyfile);
  assert (NULL != key);

  FILE *fp;
  char *k_str;
  int rc = -1;
  size_t MAX = 2048;
  size_t k_str_len;

  if (NULL == (fp = fopen (keyfile, "rb")))
    return rc;

  k_str = (char *) malloc (MAX);
  assert (NULL != k_str);
  memset (k_str, 0, MAX);

  k_str_len = fread(k_str, 1, MAX, fp);

  assert (k_str_len > 0);

  rc = gcry_sexp_build (key, NULL, k_str);

  free (k_str);
  fclose (fp);

  return rc;

}

#endif


int
lca_ecdsa_p256_hash_sign (int fd, uint8_t *data, size_t len,
                          uint8_t slot,
                          uint8_t signature[LCA_P256_COORD_SIZE*2])
{
  assert (data);
  uint8_t digest[YACL_SHA256_LEN];
  int rc = yacl_sha256 (data, len, digest);

  if (rc)
    return rc;

  struct lca_octet_buffer dig;
  dig.ptr = digest;
  dig.len = YACL_SHA256_LEN;

  if (!lca_wakeup(fd))
    return -3;

  /* Forces a seed update on the RNG */
  struct lca_octet_buffer r = lca_get_random (fd, true);

  /* Loading the nonce is the mechanism to load the SHA256
     hash into the device */
  if (load_nonce (fd, dig))
    {

      struct lca_octet_buffer rsp = lca_ecc_sign (fd, slot);

      if (NULL != rsp.ptr)
        {
          assert (YACL_P256_COORD_SIZE*2 == rsp.len);
          memcpy (signature, rsp.ptr, rsp.len);
          lca_free_octet_buffer (rsp);
          rc = 0;
        }
      else
        {
          rc = -2;
        }

    }
  else
    {
      rc = -1;
    }

  lca_idle(fd);

  return rc;
}
