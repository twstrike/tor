#include "or.h"
#include "onion_fast.h"
#include "test.h"

static void
test_fast_handshake_state_free_does_not_free_if_is_null()
{
  fast_handshake_state_t *s = NULL;

  fast_handshake_state_free(s);
  tt_ptr_op(s, OP_EQ, NULL);

  done:
  tor_free(s);
}

#define TEST_FAST_HANDSHAKE(name)                                               \
  { #name, test_fast_ ## name, 0, NULL, NULL }

struct testcase_t fast_handshake_tests[] = {
  TEST_FAST_HANDSHAKE(handshake_state_free_does_not_free_if_is_null),
  END_OF_TESTCASES
};

