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

#include "config.h"

#include <assert.h>
#include <gcrypt.h>
#include "ecdsa.h"
#include "log.h"

bool
ci2c_ecdsa_p256_verify (struct ci2c_octet_buffer pub_key,
                        struct ci2c_octet_buffer signature,
                        struct ci2c_octet_buffer sha256_digest)
{
  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  assert (64 == pub_key.len);
  assert (64 == signature.len);
  assert (32 == sha256_digest.len);

  CI2C_LOG (DEBUG, "Gcrypt init");

  gcry_sexp_t g_pub_key;
  gcry_sexp_t g_digest;
  gcry_sexp_t g_sig;
  int rc = 0;

  const int DEBUG_MAX_SIZE = 1024;

  char * debug = malloc (DEBUG_MAX_SIZE);
  memset (debug, DEBUG_MAX_SIZE, 0);

  rc = gcry_sexp_build (&g_pub_key, NULL,
                        "(public-key\n"
                        " (ecdsa\n"
                        "  (curve \"NIST P-256\")\n"
                        "  (q %b)"
                        "))", pub_key.len, pub_key);

  int bytes = gcry_sexp_sprint (g_pub_key, GCRYSEXP_FMT_ADVANCED, debug, DEBUG_MAX_SIZE);

  printf (debug);
  memset (debug, DEBUG_MAX_SIZE, 0);


  assert (0 == rc);
  CI2C_LOG (DEBUG, "built pub key");


  rc = gcry_sexp_build (&g_digest, NULL,
                        "(data (flags raw)\n"
                        " (value %b))",
                        sha256_digest.len, sha256_digest.ptr);

  assert (0 == rc);
  CI2C_LOG (DEBUG, "built hash");
  bytes = gcry_sexp_sprint (g_digest, GCRYSEXP_FMT_ADVANCED, debug, DEBUG_MAX_SIZE);

  printf (debug);
  memset (debug, DEBUG_MAX_SIZE, 0);

  rc = gcry_sexp_build (&g_sig, NULL,
                        "(sig-val(ecdsa(r %b)(s %b)))",
                        32, signature.ptr,
                        32, signature.ptr + 32);

  assert (0 == rc);
  CI2C_LOG (DEBUG, "built signature");
  bytes = gcry_sexp_sprint (g_sig, GCRYSEXP_FMT_ADVANCED, debug, DEBUG_MAX_SIZE);

  printf (debug);
  memset (debug, DEBUG_MAX_SIZE, 0);

  rc = gcry_pk_verify (g_sig, g_digest, g_pub_key);
  CI2C_LOG (DEBUG, "verify complete");
  CI2C_LOG (DEBUG, "gcry_pk_verify failed: %s", gpg_strerror (rc));

  gcry_sexp_release (g_sig);
  gcry_sexp_release (g_digest);
  gcry_sexp_release (g_pub_key);

  free (debug);

  bool result = false;

  if (rc == 0)
    result = true;

  return result;
}
