/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "config.h"
#include "dirvote.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "routerlist.h"
#include "routerparse.h"
#include "torcert.h"

#include "test.h"
#include "tortls.h"
#include "tortls.c"

static void
test_tortls_errno_to_tls_error(void *data)
{
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNRESET)),OP_EQ,TOR_TLS_ERROR_CONNRESET);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ETIMEDOUT)),OP_EQ,TOR_TLS_ERROR_TIMEOUT);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(EHOSTUNREACH)),OP_EQ,TOR_TLS_ERROR_NO_ROUTE);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ENETUNREACH)),OP_EQ,TOR_TLS_ERROR_NO_ROUTE);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNREFUSED)),OP_EQ,TOR_TLS_ERROR_CONNREFUSED);
    tt_int_op(tor_errno_to_tls_error(0),OP_EQ,TOR_TLS_ERROR_MISC);
 done:
  (void)1;
}

static void
test_tortls_err_to_string(void *data)
{
    tt_str_op(tor_tls_err_to_string(1),OP_EQ,"[Not an error.]");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_MISC),OP_EQ,"misc error");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_IO),OP_EQ,"unexpected close");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_CONNREFUSED),OP_EQ,"connection refused");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_CONNRESET),OP_EQ,"connection reset");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_NO_ROUTE),OP_EQ,"host unreachable");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_ERROR_TIMEOUT),OP_EQ,"connection timed out");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_CLOSE),OP_EQ,"closed");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_WANTREAD),OP_EQ,"want to read");
    tt_str_op(tor_tls_err_to_string(TOR_TLS_WANTWRITE),OP_EQ,"want to write");
    tt_str_op(tor_tls_err_to_string(-100),OP_EQ,"(unknown error code)");
 done:
  (void)1;
}

#define LOCAL_TEST_CASE(name) \
  { #name, test_tortls_##name, 0, NULL, NULL }

struct testcase_t tortls_tests[] = {
  LOCAL_TEST_CASE(err_to_string),
  LOCAL_TEST_CASE(errno_to_tls_error),
  END_OF_TESTCASES
};
