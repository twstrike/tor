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

static void
test_tor_tls_err_to_string(void *data)
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

struct testcase_t tortls_tests[] = {
    { "tortls", test_tor_tls_err_to_string, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
