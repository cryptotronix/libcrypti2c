#include <check.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "../libcryptoauth.h"


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


static int
fill_random(uint8_t *ptr, const int len)
{
    int rc = -1;
    int fd = open("/dev/urandom", O_RDONLY);
    size_t num = 0;

    if (fd < 0)
    {
        printf ("RNG fail with %s\n", strerror(errno));
        return rc;
    }

    while (num < len)
    {
        rc = read(fd, ptr + num, len - num);
        if (rc < 0)
        {
            return rc;
        }
        else
        {
            num += rc;
        }
    }

    close (fd);

    return len;
}

START_TEST(test_hmac)
{

    uint8_t key [32];
    uint8_t challenge [32];

    struct lca_octet_buffer k_buf;
    struct lca_octet_buffer c_buf;
    struct lca_octet_buffer result;


    ck_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key));
    ck_assert_int_eq(fill_random(challenge, sizeof(challenge)), sizeof(challenge));

    k_buf.ptr = key;
    k_buf.len = sizeof(key);

    c_buf.ptr = challenge;
    c_buf.len = sizeof(challenge);

    result = lca_soft_hmac256_defaults(c_buf, k_buf, 0);

    ck_assert_int_eq(result.len, 32);

    // Verify the result
    ck_assert(lca_verify_hmac_defaults(c_buf, result, k_buf, 0));

    // Try to verify the key, which should fail
    ck_assert(!lca_verify_hmac_defaults(c_buf, c_buf, k_buf, 0));

    // Now let's sign the hmac

    gcry_sexp_t ecc, sig;

    ck_assert(lca_gen_soft_keypair (&ecc));

    lca_set_log_level(DEBUG);
    lca_print_sexp (ecc);

    ck_assert (0 == lca_soft_sign(&ecc, result, &sig));






}
END_TEST

START_TEST(ecdsa_soft_key_pair)
{
    gcry_sexp_t ecc, sig;
    struct lca_octet_buffer result, signature;

    ck_assert(0 == lca_gen_soft_keypair (&ecc));

    lca_print_sexp (ecc);

    uint8_t key [32];

    ck_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key));

    result.ptr = key;
    result.len = sizeof(key);

    ck_assert (0 == lca_soft_sign(&ecc, result, &sig));

    lca_print_sexp (sig);

}
END_TEST

START_TEST(test_hmac_key_slot)
{

    uint8_t key [32];
    uint8_t challenge [32];
    int i, z;

    struct lca_octet_buffer k_buf;
    struct lca_octet_buffer c_buf;
    struct lca_octet_buffer result;


    ck_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key));
    ck_assert_int_eq(fill_random(challenge, sizeof(challenge)), sizeof(challenge));

    k_buf.ptr = key;
    k_buf.len = sizeof(key);

    c_buf.ptr = challenge;
    c_buf.len = sizeof(challenge);

    for (i=0; i < 16; i++)
    {
        result = lca_soft_hmac256_defaults(c_buf, k_buf, i);

        ck_assert_int_eq(result.len, 32);

        // Verify the result
        ck_assert(lca_verify_hmac_defaults(c_buf, result, k_buf, i));

        // Try to verify the key, which should fail
        if (i == 0)
            z = 15;
        else
            z = i - 1;
        ck_assert(!lca_verify_hmac_defaults(c_buf, result, k_buf, z));
    }
}
END_TEST

START_TEST(test_ecdsa_key_pair)
{
    assert (NULL != gcry_check_version (NULL));

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

  lca_print_sexp (hash);
  if ((err = gcry_sexp_new (&hash2, hash2_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  if ((err = gcry_sexp_new (&hash3, hash3_string, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  if ((err = gcry_sexp_new (&key, ecc_private_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  lca_print_sexp (key);

  if ((err = gcry_pk_sign (&sig, hash, key)))
    die ("gcry_pk_sign failed: %s", gpg_strerror (err));

  LCA_LOG (DEBUG, "Sign done");

  lca_print_sexp (sig);

  struct lca_octet_buffer h, o;

  printf("Attempt 2\n");
  ck_assert (0 == lca_soft_sign (&key, h, &o));

  gcry_sexp_release (key);
  if ((err = gcry_sexp_new (&key, ecc_public_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  lca_print_sexp (key);

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

END_TEST

void lca_hard_coded(void)
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

  lca_print_sexp (hash);
  if ((err = gcry_sexp_new (&key, ecc_public_key, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  lca_print_sexp (key);

  if ((err = gcry_sexp_new (&sig, sig_stuff, 0, 1)))
    die ("line %d: %s", __LINE__, gpg_strerror (err));

  lca_print_sexp (sig);

  if ((err = gcry_pk_verify (sig, hash, key)))
    die ("gcry_pk_verify failed: %s", gpg_strerror (err));


  gcry_sexp_release (key);
  gcry_sexp_release (sig);
  gcry_sexp_release (hash);

}


Suite * hmac_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("HMAC");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_hmac);
    tcase_add_test(tc_core, test_hmac_key_slot);
    suite_add_tcase(s, tc_core);

    return s;
}

Suite * ecdsa_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("ECDSA");

    /* Core test case */
    tc_core = tcase_create("Core");

    //tcase_add_test(tc_core, test_ecdsa_key_pair);
    tcase_add_test(tc_core, ecdsa_soft_key_pair);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s, *e;
    SRunner *sr;

    assert (NULL != gcry_check_version (NULL));

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    lca_set_log_level(DEBUG);

    //s = hmac_suite();
    e = ecdsa_suite();

    sr = srunner_create(s);
    srunner_add_suite(sr, e);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
