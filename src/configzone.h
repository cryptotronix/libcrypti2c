#ifndef _TEST_CONFIGZONE_H_
#define _TEST_CONFIGZONE_H_

#include <stdint.h>
#include "util.h"

int
config2bin(char *docname, struct lca_octet_buffer *out);

int
lca_burn_config_zone (int fd, struct lca_octet_buffer cz);


#endif
