#ifndef _OTP_H_
#define _OTP_H_

#include <stdint.h>
#include "util.h"

struct lca_octet_buffer
lca_build_otp_zone (void);

int
lca_burn_otp_zone (int fd, struct lca_octet_buffer otp_zone);

int
personalize (int fd, const char *config_file);

#endif
