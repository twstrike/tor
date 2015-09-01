/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "test.h"

#define SANDBOX_PRIVATE
#include "sandbox.h"

#include "log_test_helpers.h"

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

static void
test_sandbox_init(void *ignored)
{
  (void)ignored;
  int res;

  int previous_log = setup_capture_of_logs(LOG_WARN);

  res = sandbox_init(NULL);
  tt_int_op(res, OP_EQ, 0);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);

#if defined(__linux__)
  tt_str_op(mock_saved_log_at(0), OP_EQ, "This version of Tor was built without support for sandboxing. To build with support for sandboxing on Linux, you must have libseccomp and its necessary header files (e.g. seccomp.h).\n");
#else
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Currently, sandboxing is only implemented on Linux. The feature is disabled on your platform.\n");
#endif

 done:
  teardown_capture_of_logs(previous_log);
}


static void
test_sandbox_cfg_allow_open_filename(void *ignored)
{
  (void)ignored;
  int res;

  res = sandbox_cfg_allow_open_filename(NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

 done:
  (void)0;
}


static void
test_sandbox_cfg_allow_openat_filename(void *ignored)
{
  (void)ignored;
  int res;

  res = sandbox_cfg_allow_openat_filename(NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

 done:
  (void)0;
}


static void
test_sandbox_cfg_allow_stat_filename(void *ignored)
{
  (void)ignored;
  int res;

  res = sandbox_cfg_allow_stat_filename(NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

 done:
  (void)0;
}

static void
test_sandbox_cfg_allow_rename(void *ignored)
{
  (void)ignored;
  int res;

  res = sandbox_cfg_allow_rename(NULL, NULL, NULL);
  tt_int_op(res, OP_EQ, 0);

 done:
  (void)0;
}

static void
test_sandbox_is_active(void *ignored)
{
  (void)ignored;
  int res;

  res = sandbox_is_active();
  tt_int_op(res, OP_EQ, 0);

 done:
  (void)0;
}

static void
test_sandbox_disable_getaddrinfo_cache(void *ignored)
{
  (void)ignored;
  // This test does nothing, but it's good to see that it doesn't blow up at least
  sandbox_disable_getaddrinfo_cache();
}

#endif // USE_LIBSECCOMP

#ifdef USE_LIBSECCOMP

struct testcase_t sandbox_tests[] = {
  END_OF_TESTCASES
};

#else // USE_LIBSECCOMP

struct testcase_t sandbox_tests[] = {
  { "cfg_allow_open_filename", test_sandbox_cfg_allow_open_filename, 0, NULL, NULL },
  { "cfg_allow_openat_filename", test_sandbox_cfg_allow_openat_filename, 0, NULL, NULL },
  { "cfg_allow_stat_filename", test_sandbox_cfg_allow_stat_filename, 0, NULL, NULL },
  { "cfg_allow_rename", test_sandbox_cfg_allow_rename, 0, NULL, NULL },
  { "is_active", test_sandbox_is_active, 0, NULL, NULL },
  { "cfg_new", test_sandbox_cfg_new, 0, NULL, NULL },
  { "init", test_sandbox_init, 0, NULL, NULL },
  { "disable_getaddrinfo_cache", test_sandbox_disable_getaddrinfo_cache, 0, NULL, NULL },
  END_OF_TESTCASES
};

#endif // USE_LIBSECCOMP
