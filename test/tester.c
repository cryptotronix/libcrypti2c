#include "test_hmac.h"
#include <check.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include "../libcryptoauth.h"

int main(void)
{
    int number_failed;
    Suite *s, *e, *x;
    SRunner *sr;

    assert (NULL != gcry_check_version (NULL));

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    lca_set_log_level(DEBUG);

    s = hmac_suite();
    e = ecdsa_suite();
    x = xml_suite();

    sr = srunner_create(s);
    srunner_add_suite(sr, e);
    srunner_add_suite(sr, x);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
