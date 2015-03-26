#include <stdlib.h>
#include <argp.h>
#include <gcrypt.h>
#include <assert.h>
#include "../libcryptoauth.h"

const char *argp_program_version =
  "csu 0.1";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "cryptoauth signing utility";

/* A description of the arguments we accept. */
static char args_doc[] = "KEYFILE";

/* Number of required args */
#define NUM_ARGS 1

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  {"file",     'f', "FILE", 0,
   "FILE to hash and sign instead of stdin" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];                /* arg1 & arg2 */
  int silent, verbose;
  char *input_file;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'q': case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 'f':
      arguments->input_file = arg;
      break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= NUM_ARGS)
        /* Too many arguments. */
        argp_usage (state);

      arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < NUM_ARGS)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };

int
load_signing_key (const char *keyfile, gcry_sexp_t *key)
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

    return rc;

}

int
hash_file (FILE *fp, gcry_sexp_t *digest)
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

int
sign_file (const char *key_f, FILE *fp)
{
    int rc = -1;

    gcry_sexp_t key, digest, sig;

    if (rc = load_signing_key (key_f, &key))
        goto OUT;

    if (rc = hash_file (fp, &digest))
        goto KEY;

    if (rc = gcry_pk_sign (&sig, digest, key))
        goto DIG;

    lca_set_log_level (DEBUG);
    lca_print_sexp (sig);
    lca_set_log_level (INFO);

    gcry_free (sig);

DIG:
    gcry_free (digest);
KEY:
    gcry_free (key);
OUT:
    return rc;
}
int
main (int argc, char **argv)
{
  struct arguments arguments;
  int rc = -1;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.input_file = NULL;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  FILE *fp;

  if (NULL == arguments.input_file)
      fp = stdin;
  else if (NULL == (fp = fopen (arguments.input_file, "r")))
      exit -2;


  rc = sign_file (arguments.args[0], fp);

  exit (rc);
}
