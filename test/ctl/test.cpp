#include <common/base.hpp>
#include <ctl/ctl.h>
#include <ctl/ctl_debug.h>

using namespace umf_test;

TEST_F(test, ctl_debug) {
    initialize_debug_ctl();
    auto ctl_handler = get_debug_ctl();
    ctl_load_config_from_string(ctl_handler, NULL,
                                "debug.heap.alloc_pattern=1");

    int value = 0;
    ctl_query(ctl_handler, NULL, CTL_QUERY_PROGRAMMATIC,
              "debug.heap.alloc_pattern", CTL_QUERY_READ, &value);
    ASSERT_EQ(value, 1);

    debug_ctl_register(ctl_handler);
    deinitialize_debug_ctl();
}
