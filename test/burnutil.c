#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include "../libcryptoauth.h"

const char *argp_program_version =
  "burnutil 0.1";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "Utility for burning the config and otp zones";

/* A description of the arguments we accept. */
static char args_doc[] = "BUS";

/* Number of required args */
#define NUM_ARGS 1

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  {"file",     'f', "XMLFILE", 0,
   "XML Memory configuration file" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[NUM_ARGS];                /* arg1 & arg2 */
    int silent, verbose;
    char *display, *input_file;
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

  if (NULL == arguments.input_file)
  {
      printf("Need xml file\n");
      exit (1);
  }


  lca_init ();

  int fd = lca_atmel_setup (arguments.args[0], 0x60);

  struct lca_octet_buffer result;

  assert (0 == config2bin(arguments.args[0], &result));

  assert (0 == lca_burn_config_zone (fd, result));

  close (fd);

  rc = 0;

  exit (rc);
}
