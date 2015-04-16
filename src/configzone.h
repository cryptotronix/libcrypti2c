#ifndef _TEST_CONFIGZONE_H_
#define _TEST_CONFIGZONE_H_

#include <stdint.h>
#include "util.h"

int
lca_config2bin(const char *docname, struct lca_octet_buffer *out);

int
lca_burn_config_zone (int fd, struct lca_octet_buffer cz);

int
lca_lock_config_zone (int fd, const struct lca_octet_buffer template);


#endif
