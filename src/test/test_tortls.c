/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TORTLS_PRIVATE
#define LOG_PRIVATE
#include "orconfig.h"

#include "or.h"
#include "torlog.h"
#include "config.h"
#include "tortls.h"

#include "test.h"

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

static int
mock_tls_cert_matches_key(const tor_tls_t *tls, const tor_x509_cert_t *cert)
{
  (void) tls;
  (void) cert; // XXXX look at this.
  return 1;
}

static void
test_tortls_tor_tls_new(void *data)
{
    MOCK(tor_tls_cert_matches_key, mock_tls_cert_matches_key);
    crypto_pk_t *key1 = NULL, *key2 = NULL;
    key1 = pk_generate(2);
    key2 = pk_generate(3);

    tor_tls_t *tls;
    tt_int_op(tor_tls_context_init(TOR_TLS_CTX_IS_PUBLIC_SERVER,
                key1, key2, 86400), OP_EQ, 0);
    tls = tor_tls_new(-1, 0);
    tt_want(tls)
 done:
  UNMOCK(tor_tls_cert_matches_key);
  crypto_pk_free(key1);
  crypto_pk_free(key2);
}

#define NS_MODULE tortls
NS_DECL(void, logv, (int severity, log_domain_mask_t domain,
    const char *funcname, const char *suffix, const char *format, va_list ap));

static void
NS(logv)(int severity, log_domain_mask_t domain,
    const char *funcname, const char *suffix, const char *format,
    va_list ap)
{
    (void) severity;
    (void) domain;
    (void) funcname;
    (void) suffix;
    (void) format;
    (void) ap; // XXXX look at this.
    CALLED(logv)++;
}

static void
test_tortls_tor_tls_get_error(void *data)
{
    MOCK(tor_tls_cert_matches_key, mock_tls_cert_matches_key);
    crypto_pk_t *key1 = NULL, *key2 = NULL;
    key1 = pk_generate(2);
    key2 = pk_generate(3);

    tor_tls_t *tls;
    tt_int_op(tor_tls_context_init(TOR_TLS_CTX_IS_PUBLIC_SERVER,
                key1, key2, 86400), OP_EQ, 0);
    tls = tor_tls_new(-1, 0);
    NS_MOCK(logv);
    tt_int_op(CALLED(logv), OP_EQ, 0);
    tor_tls_get_error(tls, 0, 0,
            (const char *)"test", 0, 0);
    tt_int_op(CALLED(logv), OP_EQ, 1);

 done:
  UNMOCK(tor_tls_cert_matches_key);
  NS_UNMOCK(logv);
  crypto_pk_free(key1);
  crypto_pk_free(key2);
}

#define LOCAL_TEST_CASE(name) \
  { #name, test_tortls_##name, 0, NULL, NULL }

struct testcase_t tortls_tests[] = {
  LOCAL_TEST_CASE(errno_to_tls_error),
  LOCAL_TEST_CASE(err_to_string),
  LOCAL_TEST_CASE(tor_tls_new),
  LOCAL_TEST_CASE(tor_tls_get_error),
  END_OF_TESTCASES
};
