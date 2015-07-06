#include <check.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "../libcryptoauth.h"
#include "../src/hash.h"

typedef enum SHAversion {
    SHA1, SHA224, SHA256, SHA384, SHA512
} SHAversion;

#define HKDFTESTCOUNT 7

/* Test arrays for HKDF. */
struct hkdfhash {
    SHAversion whichSha;
    int ikmlength;
    const char *ikmarray;
    int saltlength;
    const char *saltarray;
    int infolength;
    const char *infoarray;
    int prklength;
    const char *prkarray;
    int okmlength;
    const char *okmarray;
} hkdfhashes[HKDFTESTCOUNT] = {
    {   /* RFC 5869 A.1. Test Case 1 */
        SHA256,
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        13, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
        10, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
        32, "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844A"
            "D7C2B3E5",
        42, "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56"
            "ECC4C5BF34007208D5B887185865"
    },
    {   /* RFC 5869 A.2. Test Case 2 */
        SHA256,
        80, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
            "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
            "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
            "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
            "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
            "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
        80, "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d"
            "\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b"
            "\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
            "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
            "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5"
            "\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
        80, "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd"
            "\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb"
            "\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
            "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
            "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5"
            "\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff",
        32, "06A6B88C5853361A06104C9CEB35B45C"
            "EF760014904671014A193F40C15FC244",
        82, "B11E398DC80327A1C8E7F78C596A4934"
            "4F012EDA2D4EFAD8A050CC4C19AFA97C"
            "59045A99CAC7827271CB41C65E590E09"
            "DA3275600C2F09B8367793A9ACA3DB71"
            "CC30C58179EC3E87C14C01D5C1F3434F"
            "1D87"
    },
    {   /* RFC 5869 A.3. Test Case 3 */
        SHA256,
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        0, "",
        0, "",
        32, "19EF24A32C717B167F33A91D6F648BDF"
            "96596776AFDB6377AC434C1C293CCB04",
        42, "8DA4E775A563C18F715F802A063C5A31"
            "B8A11F5C5EE1879EC3454E5F3C738D2D"
            "9D201395FAA4B61A96C8"
    },
    {   /* RFC 5869 A.4. Test Case 4 */
        SHA1,
        11, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        13, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c",
        10, "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9",
        20, "9B6C18C432A7BF8F0E71C8EB88F4B30BAA2BA243",
        42, "085A01EA1B10F36933068B56EFA5AD81"
            "A4F14B822F5B091568A9CDD4F155FDA2"
            "C22E422478D305F3F896"
    },
    {   /* RFC 5869 A.5. Test Case 5 */
        SHA1,
        80, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
            "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
            "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
            "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"
            "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45"
            "\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
        80, "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D"
            "\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B"
            "\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
            "\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97"
            "\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5"
            "\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF",
        80, "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD"
            "\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB"
            "\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9"
            "\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7"
            "\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5"
            "\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
        20, "8ADAE09A2A307059478D309B26C4115A224CFAF6",
        82, "0BD770A74D1160F7C9F12CD5912A06EB"
            "FF6ADCAE899D92191FE4305673BA2FFE"
            "8FA3F1A4E5AD79F3F334B3B202B2173C"
            "486EA37CE3D397ED034C7F9DFEB15C5E"
            "927336D0441F4C4300E2CFF0D0900B52"
            "D3B4"
    },
    {   /* RFC 5869 A.6. Test Case 6 */
        SHA1,
        22, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
            "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        0, "",
        0, "",
        20, "DA8C8A73C7FA77288EC6F5E7C297786AA0D32D01",
        42, "0AC1AF7002B3D761D1E55298DA9D0506"
            "B9AE52057220A306E07B6B87E8DF21D0"
            "EA00033DE03984D34918"
    },
    {   /* RFC 5869 A.7. Test Case 7. */
        SHA1,
        22, "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c"
            "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
        0, 0,
        0, "",
        20, "2ADCCADA18779E7C2077AD2EB19D3F3E731385DD",
        42, "2C91117204D745F3500D636A62F64F0A"
            "B3BAE548AA53D423B0D1F27EBBA6F5E5"
            "673A081D70CCE7ACFC48"
    }
};



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
    gcry_sexp_t ecc, sig, g_digest;
    struct lca_octet_buffer result;

    ck_assert(0 == lca_gen_soft_keypair (&ecc));

    lca_print_sexp (ecc);

    uint8_t key [32];

    ck_assert_int_eq(fill_random(key, sizeof(key)), sizeof(key));

    result.ptr = key;
    result.len = sizeof(key);

    ck_assert (0 == lca_soft_sign(&ecc, result, &sig));

    lca_print_sexp (sig);

    // Verify the sig
    gcry_sexp_build (&g_digest, NULL,
                     "(data (flags raw)\n"
                     " (value %b))",
                     result.len, result.ptr);

    ck_assert (0 ==  gcry_pk_verify (sig, g_digest, ecc));

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

START_TEST(t_hmac_vectors)
{
    uint8_t data[] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};
    uint8_t key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    struct lca_octet_buffer i, k;

    i.ptr = data;
    i.len = sizeof(data);

    k.ptr = key;
    k.len = sizeof(key);

    struct lca_octet_buffer r = hmac_buffer (i, k);

    ck_assert (NULL != r.ptr);

    lca_print_hex_string ("hmac: vector", r.ptr, r.len);
}
END_TEST

START_TEST(t_hkdf_extract)
{
    int rc, testno, okm_len, L;
#define MAX_OKM_LEN 82
    testno = 0;
    unsigned char prk[LCA_SHA256_DLEN+1];
    unsigned char okm[MAX_OKM_LEN+1];

    memset (okm, 0, sizeof(okm));


    uint8_t ikm[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                     0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

    uint8_t salt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, };

    rc = lca_hkdf_256_extract(salt,
                              sizeof(salt),
                              ikm,
                              sizeof(ikm),
                              prk);

    ck_assert (0 == rc);

    uint8_t prk_kat[] = {0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
                         0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
                         0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
                         0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5 };

    lca_print_hex_string("prk:", prk, LCA_SHA256_DLEN);
    lca_print_hex_string("prk_kat:", prk_kat, LCA_SHA256_DLEN);

    ck_assert (0 == memcmp (prk, prk_kat, LCA_SHA256_DLEN));


    uint8_t okm_kat[] = {0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
                         0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
                         0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
                         0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
                         0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
                         0x58, 0x65};

    uint8_t info[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};

    L = 42;

    rc = lca_hkdf_256_expand(prk, sizeof(prk),
                             info, sizeof (info),
                             okm, L);

    ck_assert (0 == rc);

    lca_print_hex_string("okm:", okm, L);
    lca_print_hex_string("okm_kat:", okm_kat, L);

    ck_assert (0 == memcmp (okm, okm_kat, L));

    rc = lca_hkdf_256_extract((const uint8_t *) hkdfhashes[testno].saltarray,
                              hkdfhashes[testno].saltlength,
                              (const uint8_t *) hkdfhashes[testno].ikmarray,
                              hkdfhashes[testno].ikmlength, prk);

    ck_assert (0 == rc);



}
END_TEST

START_TEST(t_hkdf_tc2)
{
    uint8_t ikm[]  = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
                      0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};

    uint8_t salt[] = { 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                       0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                       0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
                       0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
                       0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                       0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                       0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
                       0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
                       0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                       0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

    uint8_t info[] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
                      0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
                      0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
                      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                      0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                      0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
                      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
                      0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
                      0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

    int L = 82;

    uint8_t okm_kat[] = {0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
                         0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
                         0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
                         0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
                         0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
                         0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
                         0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
                         0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
                         0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
                         0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
                         0x1d, 0x87};

    static uint8_t okm[82] = {};

    int rc = lca_hkdf(salt, sizeof(salt),
                      ikm, sizeof(ikm),
                      info, sizeof(info),
                      okm, L);

    lca_print_hex_string ("okm:", okm, L);

    ck_assert (0 == rc);

    ck_assert (0 == memcmp (okm_kat, okm, L));

}
END_TEST


Suite * hmac_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("HMAC");

    /* Core test case */
    tc_core = tcase_create("Core");

    //tcase_add_test(tc_core, test_hmac);
    tcase_add_test(tc_core, test_hmac_key_slot);
    tcase_add_test(tc_core, t_hkdf_extract);
    tcase_add_test(tc_core, t_hmac_vectors);
    tcase_add_test(tc_core, t_hkdf_tc2);
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
