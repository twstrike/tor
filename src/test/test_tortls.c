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
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNRESET)),==,TOR_TLS_ERROR_CONNRESET);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ETIMEDOUT)),==,TOR_TLS_ERROR_TIMEOUT);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(EHOSTUNREACH)),==,TOR_TLS_ERROR_NO_ROUTE);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ENETUNREACH)),==,TOR_TLS_ERROR_NO_ROUTE);
    tt_int_op(tor_errno_to_tls_error(SOCK_ERRNO(ECONNREFUSED)),==,TOR_TLS_ERROR_CONNREFUSED);
    tt_int_op(tor_errno_to_tls_error(0),==,TOR_TLS_ERROR_MISC);
 done:
  (void)1;
}

static void
test_tortls_err_to_string(void *data)
{
    tt_int_op(strcmp(tor_tls_err_to_string(1),"[Not an error.]"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_MISC),"misc error"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_IO),"unexpected close"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_CONNREFUSED),"connection refused"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_CONNRESET),"connection reset"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_NO_ROUTE),"host unreachable"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_ERROR_TIMEOUT),"connection timed out"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_CLOSE),"closed"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_WANTREAD),"want to read"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(TOR_TLS_WANTWRITE),"want to write"), ==, 0);
    tt_int_op(strcmp(tor_tls_err_to_string(-100),"(unknown error code)"), ==, 0);
 done:
  (void)1;
}

#define NODE(name, flags) \
  { #name, test_tortls_##name, (flags), NULL, NULL }

struct testcase_t tortls_tests[] = {
  NODE(err_to_string, 0),
  NODE(errno_to_tls_error, 0),
  END_OF_TESTCASES
};
