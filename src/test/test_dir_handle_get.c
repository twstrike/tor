/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define RENDCOMMON_PRIVATE

#include "or.h"
#include "config.h"
#include "directory.h"
#include "test.h"
#include "connection.h"
#include "rendcommon.h"
#include "rendcache.h"
#include "router.h"
#include "routerlist.h"
#include "rend_test_helpers.h"
#include "microdesc.h"

#ifdef _WIN32
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif

#define NS_MODULE dir_handle_get

static void connection_write_to_buf_mock(const char *string, size_t len,
                                         connection_t *conn, int zlib)
{
  (void) zlib;

  tor_assert(string);
  tor_assert(conn);

  write_to_buf(string, len, conn->outbuf);
}

static tor_addr_t MOCK_TOR_ADDR;

static void
test_dir_handle_get_bad_request(void *data)
{
  dir_connection_t *conn = NULL;
  char *sent = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, "", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &sent, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(sent, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(sent);
}

static void
test_dir_handle_get_v1_command_without_disclaimer(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // no frontpage configured
  tt_ptr_op(get_dirportfrontpage(), OP_EQ, NULL);

  /* V1 path */
  tt_int_op(directory_handle_command_get(conn, "GET /tor/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static const char*
mock_get_dirportfrontpage(void){
  return "HELLO FROM FRONTPAGE";
}

static void
test_dir_handle_get_v1_command_returns_disclaimer(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0, body_len = 0;
  const char *exp_body = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  MOCK(get_dirportfrontpage, mock_get_dirportfrontpage);

  exp_body = get_dirportfrontpage();
  body_len = strlen(exp_body);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, "GET /tor/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, body_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/html\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 20\r\n"));

  tt_int_op(body_used, OP_EQ, body_len);
  tt_str_op(body, OP_EQ, exp_body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    UNMOCK(get_dirportfrontpage);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_unknown_path(void *data)
{
  dir_connection_t *conn = NULL;
  char *sent = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  /* Unrecognized path */
  tt_int_op(directory_handle_command_get(conn, "GET /anything HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &sent, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(sent, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(sent);
}

static void
test_dir_handle_get_robots_txt(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/robots.txt HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, 29, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 28\r\n"));

  tt_int_op(body_used, OP_EQ, 28);
  tt_str_op(body, OP_EQ, "User-agent: *\r\nDisallow: /\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_bytes_txt(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0, body_len = 0;
  char buff[30];
  char *exp_body = NULL;
  (void) data;

  exp_body = directory_dump_request_log();
  body_len = strlen(exp_body);

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/bytes.txt HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, body_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Pragma: no-cache\r\n"));
  
  sprintf(buff, "Content-Length: %ld\r\n", body_len);
  tt_assert(strstr(header, buff));

  tt_int_op(body_used, OP_EQ, body_len);
  tt_str_op(body, OP_EQ, exp_body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_rendezvous2_on_not_encrypted_conn(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is not encrypted
  tt_assert(!connection_dir_is_encrypted(conn))

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_with_invalid_desc_id(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/invalid-desc-id HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_not_well_formed(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  //TODO: this cant be reached because rend_valid_descriptor_id() prevents this
  //case to happen. This test is the same as 
  //test_dir_handle_get_rendezvous2_on_encrypted_conn_with_invalid_desc_id
  //We should refactor to remove the case from the switch.

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/1bababababababababababababababab HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_not_present(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  rend_cache_init();

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/3xqunszqnaolrrfmtzgaki7mxelgvkje HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    rend_cache_free_all();
}

NS_DECL(const routerinfo_t *, router_get_my_routerinfo, (void));
NS_DECL(int, hid_serv_responsible_for_desc_id, (const char *id));

static routerinfo_t *mock_routerinfo;
static int hid_serv_responsible_for_desc_id_response;

static const routerinfo_t *
NS(router_get_my_routerinfo)(void)
{
  if(!mock_routerinfo) {
    mock_routerinfo = tor_malloc(sizeof(routerinfo_t));
  }

  return mock_routerinfo;
}

static int
NS(hid_serv_responsible_for_desc_id)(const char *id)
{
  return hid_serv_responsible_for_desc_id_response;
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_success(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  char buff[30];
  char req[70];
  rend_encoded_v2_service_descriptor_t *desc_holder = NULL;
  char *service_id = NULL;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  size_t body_len = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  NS_MOCK(router_get_my_routerinfo);
  NS_MOCK(hid_serv_responsible_for_desc_id);

  rend_cache_init();
  hid_serv_responsible_for_desc_id_response = 1;

  /* create a valid rend service descriptor */
  #define RECENT_TIME -10
  generate_desc(RECENT_TIME, &desc_holder, &service_id, 3);

  tt_int_op(rend_cache_store_v2_desc_as_dir(desc_holder->desc_str), OP_EQ, RCS_OKAY);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  sprintf(req, "GET /tor/rendezvous2/%s HTTP/1.0\r\n\r\n", desc_id_base32);

  tt_int_op(directory_handle_command_get(conn, req, NULL, 0), OP_EQ, 0);

  body_len = strlen(desc_holder->desc_str);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, body_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Pragma: no-cache\r\n"));
  sprintf(buff, "Content-Length: %ld\r\n", body_len);
  tt_assert(strstr(header, buff));

  tt_str_op(body, OP_EQ, desc_holder->desc_str);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    NS_UNMOCK(router_get_my_routerinfo);
    NS_UNMOCK(hid_serv_responsible_for_desc_id);

    tor_free(conn);
    tor_free(header);
    tor_free(body);
    rend_cache_free_all();
}

static void
test_dir_handle_get_micro_d_missing_fingerprints(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  #define B64_256_1 "8/Pz8/u7vz8/Pz+7vz8/Pz+7u/Pz8/P7u/Pz8/P7u78"
  #define B64_256_2 "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw"
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, "GET /tor/micro/d/" B64_256_1 "-" B64_256_2 " HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);

    tor_free(conn);
    tor_free(header);
}

static or_options_t *mock_options = NULL;
static void
init_mock_options(void){
  mock_options = malloc(sizeof(or_options_t));
  memset(mock_options, 0, sizeof(or_options_t));
  mock_options->TestingTorNetwork = 1;
}

static const or_options_t *
mock_get_options(void)
{
  tor_assert(mock_options);
  return mock_options;
}

static const char microdesc[] =
  "onion-key\n"
  "-----BEGIN RSA PUBLIC KEY-----\n"
  "MIGJAoGBAMjlHH/daN43cSVRaHBwgUfnszzAhg98EvivJ9Qxfv51mvQUxPjQ07es\n"
  "gV/3n8fyh3Kqr/ehi9jxkdgSRfSnmF7giaHL1SLZ29kA7KtST+pBvmTpDtHa3ykX\n"
  "Xorc7hJvIyTZoc1HU+5XSynj3gsBE5IGK1ZRzrNS688LnuZMVp1tAgMBAAE=\n"
  "-----END RSA PUBLIC KEY-----\n";

static void
test_dir_handle_get_micro_d_finds_fingerprints(void *data)
{
  or_options_t *options = NULL;
  dir_connection_t *conn = NULL;
  microdesc_cache_t *mc = NULL ;
  smartlist_t *list = NULL;
  char digest[DIGEST256_LEN];
  char digest_base64[128];
  char path[80];
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  options = get_options_mutable();
  tt_assert(options);
  tor_free(options->DataDirectory);
  options->DataDirectory = tor_strdup(get_fname("dir_datadir_test"));
#ifdef _WIN32
  tt_int_op(0, OP_EQ, mkdir(options->DataDirectory));
#else
  tt_int_op(0, OP_EQ, mkdir(options->DataDirectory, 0700));
#endif

  /* Add microdesc to cache */
  crypto_digest256(digest, microdesc, strlen(microdesc), DIGEST_SHA256);
  base64_encode(digest_base64, sizeof(digest_base64), digest, DIGEST256_LEN, 0);

  //replace the padding = by 0
  digest_base64[43] = 0;

  mc = get_microdesc_cache();
  list = microdescs_add_to_cache(mc, microdesc, NULL, SAVED_NOWHERE, 0,
                                  time(NULL), NULL);
  tt_int_op(1, OP_EQ, smartlist_len(list));


  /* Make the request */
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  sprintf(path, "GET /tor/micro/d/%s HTTP/1.0\r\n\r\n", digest_base64);
  tt_int_op(directory_handle_command_get(conn, path, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(microdesc)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  tt_str_op(body, OP_EQ, microdesc);

  done:
    UNMOCK(connection_write_to_buf_impl_);

    tor_free(conn);
    tor_free(header);
    tor_free(body);
    tor_free(mc);
    tor_free(options);
    smartlist_free(list);
}

#define DIR_HANDLE_CMD(name,flags)                              \
  { #name, test_dir_handle_get_##name, (flags), NULL, NULL }

struct testcase_t dir_handle_get_tests[] = {
  DIR_HANDLE_CMD(bad_request, 0),
  DIR_HANDLE_CMD(v1_command_without_disclaimer, 0),
  DIR_HANDLE_CMD(v1_command_returns_disclaimer, 0),
  DIR_HANDLE_CMD(unknown_path, 0),
  DIR_HANDLE_CMD(robots_txt, 0),
  DIR_HANDLE_CMD(bytes_txt, 0),
  DIR_HANDLE_CMD(rendezvous2_on_not_encrypted_conn, 0),
  DIR_HANDLE_CMD(rendezvous2_on_encrypted_conn_with_invalid_desc_id, 0),
  DIR_HANDLE_CMD(rendezvous2_on_encrypted_conn_not_well_formed, 0),
  DIR_HANDLE_CMD(rendezvous2_on_encrypted_conn_not_present, 0),
  DIR_HANDLE_CMD(rendezvous2_on_encrypted_conn_success, 0),
  DIR_HANDLE_CMD(micro_d_missing_fingerprints, TT_FORK),
  DIR_HANDLE_CMD(micro_d_finds_fingerprints, TT_FORK),
  END_OF_TESTCASES
};
