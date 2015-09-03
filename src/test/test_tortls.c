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
#include "log_test_helpers.h"

#include <openssl/err.h>

#define NS_MODULE tortls

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

static void
test_tortls_get_state_description(void *ignored)
{
  (void)ignored;
  tor_tls_t *tls;
  char *buf;
  SSL_CTX *ctx;

  SSL_library_init();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(SSLv23_method());

  buf = tor_malloc_zero(1000);
  tls = tor_malloc_zero(sizeof(tor_tls_t));

  tor_tls_get_state_description(NULL, buf, 20);
  tt_str_op(buf, OP_EQ, "(No SSL object)");

  tls->ssl = NULL;
  tor_tls_get_state_description(tls, buf, 20);
  tt_str_op(buf, OP_EQ, "(No SSL object)");

  tls->ssl = SSL_new(ctx);
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in HANDSHAKE");

  tls->state = TOR_TLS_ST_OPEN;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in OPEN");

  tls->state = TOR_TLS_ST_GOTCLOSE;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in GOTCLOSE");

  tls->state = TOR_TLS_ST_SENTCLOSE;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in SENTCLOSE");

  tls->state = TOR_TLS_ST_CLOSED;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in CLOSED");

  tls->state = TOR_TLS_ST_RENEGOTIATE;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in RENEGOTIATE");

  tls->state = TOR_TLS_ST_BUFFEREVENT;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization");

  tls->state = 7;
  tor_tls_get_state_description(tls, buf, 200);
  tt_str_op(buf, OP_EQ, "before/accept initialization in unknown TLS state");

 done:
  SSL_CTX_free(ctx);
  tor_free(buf);
  tor_free(tls);
}

extern int tor_tls_object_ex_data_index;

static void
test_tortls_get_by_ssl(void *ignored)
{
  (void)ignored;
  tor_tls_t *tls;
  tor_tls_t *res;
  SSL_CTX *ctx;
  SSL *ssl;

  SSL_library_init();
  SSL_load_error_strings();
  tor_tls_allocate_tor_tls_object_ex_data_index();

  ctx = SSL_CTX_new(SSLv23_method());
  tls = tor_malloc_zero(sizeof(tor_tls_t));
  tls->magic = TOR_TLS_MAGIC;

  ssl = SSL_new(ctx);

  res = tor_tls_get_by_ssl(ssl);
  tt_assert(!res);

  SSL_set_ex_data(ssl, tor_tls_object_ex_data_index, tls);

  res = tor_tls_get_by_ssl(ssl);
  tt_assert(res == tls);

 done:
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  tor_free(tls);
}

static void
test_tortls_allocate_tor_tls_object_ex_data_index(void *ignored)
{
  (void)ignored;
  int first;

  tor_tls_allocate_tor_tls_object_ex_data_index();

  first = tor_tls_object_ex_data_index;
  tor_tls_allocate_tor_tls_object_ex_data_index();
  tt_int_op(first, OP_EQ, tor_tls_object_ex_data_index);

 done:
  (void)0;
}

static void
test_tortls_log_one_error(void *ignored)
{
  (void)ignored;
  tor_tls_t *tls;
  SSL_CTX *ctx;
  SSL *ssl = NULL;

  SSL_library_init();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(SSLv23_method());
  tls = tor_malloc_zero(sizeof(tor_tls_t));
  int previous_log = setup_capture_of_logs(LOG_INFO);

  tor_tls_log_one_error(NULL, 0, LOG_WARN, 0, "something");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error while something: (null) (in (null):(null):---)\n");

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, 0, LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error: (null) (in (null):(null):---)\n");

  mock_clean_saved_logs();
  tls->address = "127.hello";
  tor_tls_log_one_error(tls, 0, LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error with 127.hello: (null) (in (null):(null):---)\n");


  mock_clean_saved_logs();
  tls->address = "127.hello";
  tor_tls_log_one_error(tls, 0, LOG_WARN, 0, "blarg");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error while blarg with 127.hello: (null) (in (null):(null):---)\n");

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, 3), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error with 127.hello: BN lib (in unknown library:(null):---)\n");

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_HTTP_REQUEST), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_HTTPS_PROXY_REQUEST), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_RECORD_LENGTH_MISMATCH), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_RECORD_TOO_LARGE), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_UNKNOWN_PROTOCOL), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, ERR_PACK(1, 2, SSL_R_UNSUPPORTED_PROTOCOL), LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  tls->ssl = SSL_new(ctx);

  mock_clean_saved_logs();
  tor_tls_log_one_error(tls, 0, LOG_WARN, 0, NULL);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error with 127.hello: (null) (in (null):(null):before/accept initialization)\n");

 done:
  teardown_capture_of_logs(previous_log);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  tor_free(tls);
}

static void
test_tortls_get_error(void *ignored)
{
  (void)ignored;
  tor_tls_t *tls;
  int ret;
  SSL_CTX *ctx;

  SSL_library_init();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(SSLv23_method());
  int previous_log = setup_capture_of_logs(LOG_INFO);
  tls = tor_malloc_zero(sizeof(tor_tls_t));
  tls->ssl = SSL_new(ctx);
  SSL_set_bio(tls->ssl, BIO_new(BIO_s_mem()), NULL);

  ret = tor_tls_get_error(tls, 0, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, TOR_TLS_ERROR_IO);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error: unexpected close while something (before/accept initialization)\n");

  mock_clean_saved_logs();
  ret = tor_tls_get_error(tls, 2, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

  mock_clean_saved_logs();
  ret = tor_tls_get_error(tls, 0, 1, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, -11);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

  mock_clean_saved_logs();
  ERR_clear_error();
  ERR_put_error(ERR_LIB_BN, 2, -1, "somewhere.c", 99);
  ret = tor_tls_get_error(tls, 0, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, TOR_TLS_ERROR_MISC);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error while something: (null) (in bignum routines:(null):before/accept initialization)\n");

  mock_clean_saved_logs();
  ERR_clear_error();
  tls->ssl->rwstate = SSL_READING;
  SSL_get_rbio(tls->ssl)->flags = BIO_FLAGS_READ;
  ret = tor_tls_get_error(tls, -1, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, TOR_TLS_WANTREAD);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

  mock_clean_saved_logs();
  ERR_clear_error();
  tls->ssl->rwstate = SSL_READING;
  SSL_get_rbio(tls->ssl)->flags = BIO_FLAGS_WRITE;
  ret = tor_tls_get_error(tls, -1, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, TOR_TLS_WANTWRITE);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);


  mock_clean_saved_logs();
  ERR_clear_error();
  tls->ssl->rwstate = 0;
  tls->ssl->shutdown = SSL_RECEIVED_SHUTDOWN;
  tls->ssl->s3->warn_alert =SSL_AD_CLOSE_NOTIFY;
  ret = tor_tls_get_error(tls, 0, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, TOR_TLS_CLOSE);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);

  mock_clean_saved_logs();
  ret = tor_tls_get_error(tls, 0, 2, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, -10);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

  mock_clean_saved_logs();
  ERR_put_error(ERR_LIB_SYS, 2, -1, "somewhere.c", 99);
  ret = tor_tls_get_error(tls, -1, 0, "something", LOG_WARN, 0);
  tt_int_op(ret, OP_EQ, -9);
  tt_int_op(mock_saved_log_number(), OP_EQ, 2);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "TLS error: <syscall error while something> (errno=0: Success; state=before/accept initialization)\n");
  tt_str_op(mock_saved_log_at(1), OP_EQ, "TLS error while something: (null) (in system library:connect:before/accept initialization)\n");

 done:
  teardown_capture_of_logs(previous_log);
  tor_free(tls);
}

static void
test_tortls_always_accept_verify_cb(void *ignored)
{
  (void)ignored;
  int ret;

  ret = always_accept_verify_cb(0, NULL);
  tt_int_op(ret, OP_EQ, 1);

 done:
  (void)0;
}


static void
test_tortls_x509_cert_free(void *ignored)
{
  (void)ignored;
  tor_x509_cert_t *cert;

  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  tor_x509_cert_free(cert);

  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  cert->cert = tor_malloc_zero(sizeof(X509));
  cert->encoded = tor_malloc_zero(1);
  tor_x509_cert_free(cert);
}

static void
test_tortls_x509_cert_get_id_digests(void *ignored)
{
  (void)ignored;
  tor_x509_cert_t *cert;
  digests_t *d;
  const digests_t *res;
  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  d = tor_malloc_zero(sizeof(digests_t));
  d->d[0][0] = 42;

  res = tor_x509_cert_get_id_digests(cert);
  tt_assert(!res);

  cert->pkey_digests_set = 1;
  cert->pkey_digests = *d;
  res = tor_x509_cert_get_id_digests(cert);
  tt_int_op(res->d[0][0], OP_EQ, 42);

 done:
  (void)0;
}

static int
fixed_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
  return 1;
}

static void
test_tortls_cert_matches_key(void *ignored)
{
  (void)ignored;
  int res;
  tor_tls_t *tls;
  tor_x509_cert_t *cert;
  X509 *one, *two;
  EVP_PKEY_ASN1_METHOD *meth = EVP_PKEY_asn1_new(999, 0, NULL, NULL);
  EVP_PKEY_asn1_set_public(meth, NULL, NULL, fixed_pub_cmp, NULL, NULL, NULL);

  tls = tor_malloc_zero(sizeof(tor_tls_t));
  cert = tor_malloc_zero(sizeof(tor_x509_cert_t));
  one = tor_malloc_zero(sizeof(X509));
  one->references = 1;
  two = tor_malloc_zero(sizeof(X509));
  two->references = 1;

  res = tor_tls_cert_matches_key(tls, cert);
  tt_int_op(res, OP_EQ, 0);

  tls->ssl = tor_malloc_zero(sizeof(SSL));
  tls->ssl->session = tor_malloc_zero(sizeof(SSL_SESSION));
  tls->ssl->session->peer = one;
  res = tor_tls_cert_matches_key(tls, cert);
  tt_int_op(res, OP_EQ, 0);

  cert->cert = two;
  res = tor_tls_cert_matches_key(tls, cert);
  tt_int_op(res, OP_EQ, 0);

  one->cert_info = tor_malloc_zero(sizeof(X509_CINF));
  one->cert_info->key = tor_malloc_zero(sizeof(X509_PUBKEY));
  one->cert_info->key->pkey = tor_malloc_zero(sizeof(EVP_PKEY));
  one->cert_info->key->pkey->references = 1;
  one->cert_info->key->pkey->ameth = meth;
  one->cert_info->key->pkey->type = 1;

  two->cert_info = tor_malloc_zero(sizeof(X509_CINF));
  two->cert_info->key = tor_malloc_zero(sizeof(X509_PUBKEY));
  two->cert_info->key->pkey = tor_malloc_zero(sizeof(EVP_PKEY));
  two->cert_info->key->pkey->references = 1;
  two->cert_info->key->pkey->ameth = meth;
  two->cert_info->key->pkey->type = 2;

  res = tor_tls_cert_matches_key(tls, cert);
  tt_int_op(res, OP_EQ, 0);

  one->cert_info->key->pkey->type = 1;
  two->cert_info->key->pkey->type = 1;
  res = tor_tls_cert_matches_key(tls, cert);
  tt_int_op(res, OP_EQ, 1);

 done:
  EVP_PKEY_asn1_free(meth);
  tor_free(tls);
  tor_free(cert);
}

#define LOCAL_TEST_CASE(name, flags)                  \
  { #name, test_tortls_##name, (flags), NULL, NULL }

struct testcase_t tortls_tests[] = {
  LOCAL_TEST_CASE(errno_to_tls_error, 0),
  LOCAL_TEST_CASE(err_to_string, 0),
  LOCAL_TEST_CASE(tor_tls_new, 0),
  LOCAL_TEST_CASE(tor_tls_get_error, 0),
  LOCAL_TEST_CASE(get_state_description, TT_FORK),
  LOCAL_TEST_CASE(get_by_ssl, TT_FORK),
  LOCAL_TEST_CASE(allocate_tor_tls_object_ex_data_index, TT_FORK),
  LOCAL_TEST_CASE(log_one_error, TT_FORK),
  LOCAL_TEST_CASE(get_error, TT_FORK),
  LOCAL_TEST_CASE(always_accept_verify_cb, 0),
  LOCAL_TEST_CASE(x509_cert_free, 0),
  LOCAL_TEST_CASE(x509_cert_get_id_digests, 0),
   LOCAL_TEST_CASE(cert_matches_key, 0),
  END_OF_TESTCASES
};
