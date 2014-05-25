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

void
ci2c_print_sexp (gcry_sexp_t to_print) {

  if (!ci2c_is_debug)
    return;

  const int DEBUG_MAX_SIZE = 1024;
  char * debug = malloc (DEBUG_MAX_SIZE);
  memset (debug, DEBUG_MAX_SIZE, 0);
  int bytes = gcry_sexp_sprint (to_print,
                                GCRYSEXP_FMT_ADVANCED,
                                debug,
                                DEBUG_MAX_SIZE);
  CI2C_LOG (DEBUG, "%s", debug);
  free (debug);
}

bool
ci2c_ecdsa_p256_verify (struct ci2c_octet_buffer pub_key,
                        struct ci2c_octet_buffer signature,
                        struct ci2c_octet_buffer sha256_digest)
{
  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  if (ci2c_is_debug())
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

  assert (65 == pub_key.len); /* +1 for uncompressed point tag */
  assert (64 == signature.len);
  assert (32 == sha256_digest.len);

  CI2C_LOG (DEBUG, "Gcrypt init");

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

  ci2c_print_sexp (g_pub_key);

  assert (0 == rc);

  rc = gcry_sexp_build (&g_digest, NULL,
                        "(data (flags raw)\n"
                        " (value %b))",
                        sha256_digest.len, sha256_digest.ptr);

  assert (0 == rc);

  ci2c_print_sexp (g_digest);

  rc = gcry_sexp_build (&g_sig, NULL,
                        "(sig-val(ecdsa(r %b)(s %b)))",
                        32, signature.ptr,
                        32, signature.ptr + 32);

  assert (0 == rc);

  ci2c_print_sexp( g_sig );

  rc = gcry_pk_verify (g_sig, g_digest, g_pub_key);
  CI2C_LOG (DEBUG, "verify complete");
  if (0 != rc)
    CI2C_LOG (DEBUG, "gcry_pk_verify failed: %s", gpg_strerror (rc));
  else
    CI2C_LOG (DEBUG, "gcry_pk_verify success");

  gcry_sexp_release (g_sig);
  gcry_sexp_release (g_digest);
  gcry_sexp_release (g_pub_key);

  return (rc == 0) ? true : false;
}

static void
die (const char *format, ...)
{
  va_list arg_ptr ;

  va_start( arg_ptr, format ) ;
  vfprintf (stderr, format, arg_ptr );
  va_end(arg_ptr);
  if (*format && format[strlen(format)-1] != '\n')
    putc ('\n', stderr);
  exit (1);
}

void ci2c_ecda_test ()
{

  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

    static const char ecc_private_key[] =
    "(private-key\n"
    " (ecdsa\n"
    "  (curve \"NIST P-256\")\n"
    "  (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2BEB6644D3609FC781"
    "B71F9A8072F58CB66AE2F89BB12451873ABF7D91F9E1FBF96BF2F70E73AAC9A283#)\n"
    "  (d #5A1EF0035118F19F3110FB81813D3547BCE1E5BCE77D1F744715E1D5BBE70378#)"
    "))";
  static const char ecc_private_key_wo_q[] =
    "(private-key\n"
    " (ecdsa\n"
    "  (curve \"NIST P-256\")\n"
    "  (d #5A1EF0035118F19F3110FB81813D3547BCE1E5BCE77D1F744715E1D5BBE70378#)"
    "))";
  static const char ecc_public_key[] =
    "(public-key\n"
    " (ecdsa\n"
    "  (curve \"NIST P-256\")\n"
    "  (q #04D4F6A6738D9B8D3A7075C1E4EE95015FC0C9B7E4272D2BEB6644D3609FC781"
    "B71F9A8072F58CB66AE2F89BB12451873ABF7D91F9E1FBF96BF2F70E73AAC9A283#)"
    "))";
  static const char hash_string[] =
    "(data (flags raw)\n"
    " (value #00112233445566778899AABBCCDDEEFF"
    /* */    "000102030405060708090A0B0C0D0E0F#))";
  static const char my_string[] =
    "(data (flags raw)\n"
    " (value #84D96682895B83EB1E5FEB085D67842D"
             "23C6150A85AC637F3090772CFAD3E6BE#))";

  static const char hash2_string[] =
    "(data (flags raw)\n"
    " (hash sha1 #00112233445566778899AABBCCDDEEFF"
    /* */    "000102030405060708090A0B0C0D0E0F"
    /* */    "000102030405060708090A0B0C0D0E0F"
    /* */    "00112233445566778899AABBCCDDEEFF#))";
  /* hash2, but longer than curve length, so it will be truncated */
  static const char hash3_string[] =
    "(data (flags raw)\n"
    " (hash sha1 #00112233445566778899AABBCCDDEEFF"
    /* */    "000102030405060708090A0B0C0D0E0F"
    /* */    "000102030405060708090A0B0C0D0E0F"
    /* */    "00112233445566778899AABBCCDDEEFF"
    /* */    "000102030405060708090A0B0C0D0E0F#))";

  gpg_error_t err;
  gcry_sexp_t key, hash, hash2, hash3, sig, sig2;

  static bool verbose = true;

  if (verbose)
    fprintf (stderr, "Checking sample ECC key.\n");

  if ((err = gcry_sexp_new (&hash, my_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (hash);
  if ((err = gcry_sexp_new (&hash2, hash2_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  if ((err = gcry_sexp_new (&hash3, hash3_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  if ((err = gcry_sexp_new (&key, ecc_private_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (key);

  if ((err = gcry_pk_sign (&sig, hash, key)))
    die ("gcry_pk_sign failed: %s", gpg_strerror (err));

  CI2C_LOG (DEBUG, "Sign done");

  ci2c_print_sexp (sig);

  gcry_sexp_release (key);
  if ((err = gcry_sexp_new (&key, ecc_public_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (key);

  if ((err = gcry_pk_verify (sig, hash, key)))
    die ("gcry_pk_verify failed: %s", gpg_strerror (err));


  gcry_sexp_release (key);
  /* if ((err = gcry_sexp_new (&key, ecc_private_key, 0, 1))) */
  /*   die ("line %d: %s", __LINE__, gpg_strerror (err)); */

  /* if ((err = gcry_pk_sign (&sig2, hash2, key))) */
  /*   die ("gcry_pk_sign failed: %s", gpg_strerror (err)); */

  /* if ((err = gcry_pk_verify (sig2, hash3, key))) */
  /*   die ("gcry_pk_verify failed: %s", gpg_strerror (err)); */

  gcry_sexp_release (sig);
  gcry_sexp_release (sig2);
  gcry_sexp_release (hash);
  gcry_sexp_release (hash2);
  gcry_sexp_release (hash3);


}


void ci2c_hard_coded()
{

  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

    static const char ecc_public_key[] =
    "(public-key\n"
    " (ecdsa\n"
    "  (curve \"NIST P-256\")\n"
      "  (q #049B4A517704E16F3C99C6973E29F882EAF840DCD125C725C9552148A74349EB77BECB37AA2DB8056BAF0E236F6DCFEC2C5A9A0F23CEFD8A9DC1F4693718E725D2#)\n"
    "))";
  static const char my_string[] =
    "(data (flags raw)\n"
    " (value #84D96682895B83EB1E5FEB085D67842D"
             "23C6150A85AC637F3090772CFAD3E6BE#))";

  static const char sig_stuff[]=
    "(sig-val\n"
    "(ecdsa\n"
    "(r #143D855553442E87D96FEF4046F07EEB8E754D4C338C007BBDC492382018ED03#)\n"
    "(s #15C2AED254A521DEE0072DE8F7485FC25806692355329CF878771DEFC6E61702#)))";

  gpg_error_t err;
  gcry_sexp_t key, hash, sig, sig2;

  static bool verbose = true;

  if (verbose)
    fprintf (stderr, "Checking hard coded ECC key.\n");

  if ((err = gcry_sexp_new (&hash, my_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (hash);
  if ((err = gcry_sexp_new (&key, ecc_public_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (key);

  if ((err = gcry_sexp_new (&sig, sig_stuff, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  ci2c_print_sexp (sig);

  if ((err = gcry_pk_verify (sig, hash, key)))
    die ("gcry_pk_verify failed: %s", gpg_strerror (err));


  gcry_sexp_release (key);
  gcry_sexp_release (sig);
  gcry_sexp_release (hash);

}

struct ci2c_octet_buffer
ci2c_add_uncompressed_point_tag (struct ci2c_octet_buffer q)
{
  assert (NULL != q.ptr);
  assert (64 == q.len); /* only support P256 now */

  struct ci2c_octet_buffer new_q = ci2c_make_buffer (65);

  new_q.ptr[0] = 0x04;

  memcpy (new_q.ptr + 1, q.ptr, q.len);

  ci2c_free_octet_buffer (q);

  return new_q;

}
