#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include "../libcryptoauth.h"

const char *argp_program_version =
  "ecdh 0.1";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "Utility for performing ecdh on the chip";

/* A description of the arguments we accept. */
static char args_doc[] = "BUS";

/* Number of required args */
#define NUM_ARGS 1

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"slot",   's', 0,      0, "specify the slot" },
  {"gen-key",     'g', 0,      0,  "generates a new key"},
  {"personalize",     'p', 0,      0,  "Fully personalizes device"},
  {"file",     'f', "XMLFILE", 0,
   "XML Memory configuration file" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
    char *args[NUM_ARGS];                /* arg1 & arg2 */
    int silent, verbose, lock, personalize, slot, gen_key;
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
    case 'q':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 's':
        arguments->slot =  atoi(arg);
      break;
    case 'g':
        arguments->gen_key = 1;
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

void
genkey(int slot, int fd)
{
    struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd,
                                                       slot,
                                                       true);

    /* There appears to be a bug on the chip where generate one key sets
       the updateCount in such a way that signatures fail. The interim fix
       is to generate two keys and discard the first. */
    pub_key = lca_gen_ecc_key (fd, slot, true);

    lca_set_log_level (DEBUG);
    lca_print_hex_string ("Pub Key: ", pub_key.ptr, pub_key.len);
    //lca_set_log_level (INFO);
}

int
main (int argc, char **argv)
{
  struct arguments arguments;
  int rc = -1;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.lock = 0;
  arguments.personalize = 0;
  arguments.slot = 1;
  arguments.gen_key = 0;
  arguments.input_file = NULL;


  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  static uint8_t x[] = {
      0xEE, 0xD1, 0xCB, 0x62, 0x9C, 0xF8, 0x7F, 0x8B,
      0xF6, 0x41, 0x99, 0x86, 0xF9, 0x90, 0xB9, 0x2E,
      0xA3, 0xDF, 0xA1, 0x4C, 0xDA, 0xF7, 0x0E, 0xB3,
      0xE8, 0xDA, 0x8F, 0x9C, 0x95, 0x04, 0xDB, 0xC5
  };

  static uint8_t y[] = {
      0xB0, 0x40, 0xD6, 0x48, 0x0E, 0x88, 0xF8, 0x95,
      0xE9, 0xE1, 0xD4, 0x47, 0x79, 0x70, 0x32, 0x9B,
      0x06, 0x04, 0x50, 0xC8, 0x0E, 0x18, 0x16, 0xEF,
      0xED, 0x7B, 0x0F, 0xA4, 0x98, 0x68, 0xCA, 0xEB
  };

  struct lca_octet_buffer x_buf, y_buf;
  x_buf.ptr = x; x_buf.len = sizeof(x);
  y_buf.ptr = y; y_buf.len = sizeof(y);

  lca_set_log_level (DEBUG);

  lca_init ();

  int fd = lca_atmel_setup (arguments.args[0], 0x60);

  struct lca_octet_buffer cz =
    get_config_zone (fd);

  lca_print_hex_string ("cz:", cz.ptr, cz.len);

  if (arguments.gen_key)
      genkey(arguments.slot, fd);

  struct lca_octet_buffer s =
      lca_ecdh (fd, arguments.slot, x_buf, y_buf);

  assert (s.ptr);

  close (fd);

  exit (0);
}

