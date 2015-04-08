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
  {"hash",     'h', 0,      0,  "Show intermediate hash output" },
  {"display",  'd', "DISPLAY", 0,
   "DISPLAY option for the result" },
  {"file",     'f', "FILE", 0,
   "FILE to hash and sign instead of stdin" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];                /* arg1 & arg2 */
  int silent, verbose, hash;
  char *input_file;
  char *display;
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
    case 'h':
      arguments->hash = 1;
      break;
    case 'f':
      arguments->input_file = arg;
      break;
    case 'd':
      arguments->display = arg;
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


void
display_sig (const gcry_sexp_t* sig, const char *d_opt)
{
    assert (NULL != d_opt);

    if (0 == strcmp (d_opt, "sexp"))
    {
        lca_set_log_level (DEBUG);
        lca_print_sexp (*sig);
        lca_set_log_level (INFO);
    }
    else if (0 == strcmp (d_opt, "hex"))
    {
        struct lca_octet_buffer r;
        struct lca_octet_buffer s;

        if (0 == lca_ssig2buffer (sig, &r, &s))
        {
            int i;
            for (i = 0; i < r.len; i++)
            {
                if (i > 0) printf(" ");
                printf("0x%02X", r.ptr[i]);
            }

            for (i = 0; i < s.len; i++)
            {
                if (i > 0) printf(" ");
                printf("0x%02X", s.ptr[i]);
            }
        }

        printf("\n");


    }
}

int
sign_file (const char *key_f, FILE *fp, gcry_sexp_t *sig, int show_digest)
{
    int rc = -1;

    gcry_sexp_t key, digest;

    if (rc = lca_load_signing_key (key_f, &key))
        goto OUT;

    if (rc = lca_hash_file (fp, &digest))
        goto KEY;

    if (show_digest)
    {
        lca_set_log_level (DEBUG);
        lca_print_sexp (digest);
        lca_set_log_level (INFO);
    }


    if (rc = gcry_pk_sign (sig, digest, key))
        goto DIG;

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
  gcry_sexp_t sig;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.hash = 0;
  arguments.input_file = NULL;
  arguments.display = "sexp";

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  FILE *fp;

  if (NULL == arguments.input_file)
      fp = stdin;
  else if (NULL == (fp = fopen (arguments.input_file, "r")))
      exit -2;


  if (0 == (rc = sign_file (arguments.args[0], fp, &sig, arguments.hash)))
  {
      display_sig (&sig, arguments.display);
  }



  exit (rc);
}
