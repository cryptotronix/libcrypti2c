#include <gcrypt.h>
#include <assert.h>
#include "../libcryptoauth.h"

void
lca_init (void)
{

    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        assert (NULL != gcry_check_version (NULL));

        gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
        gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
        gcry_control (GCRYCTL_RESUME_SECMEM_WARN);


        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

        if (lca_is_debug())
            gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);

        gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    }
}

void
lca_init_and_debug (enum LCA_LOG_LEVEL lvl)
{
    lca_set_log_level (lvl);

    lca_init();
}
