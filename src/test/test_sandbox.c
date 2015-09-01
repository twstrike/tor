/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "test.h"

#define SANDBOX_PRIVATE
#include "sandbox.h"

#define NS_MODULE sandbox

#ifdef USE_LIBSECCOMP

#else // USE_LIBSECCOMP

static void
test_sandbox_cfg_new(void *ignored)
{
  (void)ignored;
  sandbox_cfg_t *res;

  res = sandbox_cfg_new();

  tt_assert(!res);

 done:
  (void)0;
}



#endif // USE_LIBSECCOMP

#ifdef USE_LIBSECCOMP

struct testcase_t sandbox_tests[] = {
  END_OF_TESTCASES
};

#else // USE_LIBSECCOMP

struct testcase_t sandbox_tests[] = {
  { "cfg_new", test_sandbox_cfg_new, 0, NULL, NULL },
  END_OF_TESTCASES
};

#endif // USE_LIBSECCOMP
