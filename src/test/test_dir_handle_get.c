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
#include "test_helpers.h"
#include "nodelist.h"
#include "entrynodes.h"
#include "routerparse.h"

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

#define GET(path) "GET " path " HTTP/1.0\r\n\r\n"
#define NOT_FOUND "HTTP/1.0 404 Not found\r\n\r\n"
#define BAD_REQUEST "HTTP/1.0 400 Bad request\r\n\r\n"
#define SERVER_BUSY "HTTP/1.0 503 Directory busy, try again later\r\n\r\n"

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

  tt_str_op(sent, OP_EQ, BAD_REQUEST);

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
  tt_int_op(directory_handle_command_get(conn, GET("/tor/"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

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
  tt_int_op(directory_handle_command_get(conn, GET("/tor/"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, body_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/html\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 20\r\n"));

  tt_int_op(body_used, OP_EQ, strlen(body));
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
  tt_int_op(directory_handle_command_get(conn, GET("/anything"), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &sent, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(sent, OP_EQ, NOT_FOUND);

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

  tt_int_op(directory_handle_command_get(conn, GET("/tor/robots.txt"), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, 29, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 28\r\n"));

  tt_int_op(body_used, OP_EQ, strlen(body));
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

  tt_int_op(directory_handle_command_get(conn, GET("/tor/bytes.txt"), NULL, 0), OP_EQ, 0);
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

  tt_int_op(body_used, OP_EQ, strlen(body));
  tt_str_op(body, OP_EQ, exp_body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

#define RENDEZVOUS2_GET(descid) GET("/tor/rendezvous2/" descid)
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

  tt_int_op(directory_handle_command_get(conn, RENDEZVOUS2_GET(), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

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

  tt_int_op(directory_handle_command_get(conn, RENDEZVOUS2_GET("invalid-desc-id"), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, BAD_REQUEST);

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

  tt_int_op(directory_handle_command_get(conn, RENDEZVOUS2_GET("1bababababababababababababababab"), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, BAD_REQUEST);

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

  tt_int_op(directory_handle_command_get(conn, RENDEZVOUS2_GET("3xqunszqnaolrrfmtzgaki7mxelgvkje"), NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

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

  sprintf(req, RENDEZVOUS2_GET("%s"), desc_id_base32);

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

  tt_int_op(body_used, OP_EQ, strlen(body));
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

#define MICRODESC_GET(digest) GET("/tor/micro/d/" digest)
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
  tt_int_op(directory_handle_command_get(conn, MICRODESC_GET(B64_256_1 "-" B64_256_2), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

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

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  init_mock_options();
  mock_options->DataDirectory = tor_strdup(get_fname("dir_handle_datadir_test1"));

#ifdef _WIN32
  tt_int_op(0, OP_EQ, mkdir(mock_options->DataDirectory));
#else
  tt_int_op(0, OP_EQ, mkdir(mock_options->DataDirectory, 0700));
#endif

  /* Add microdesc to cache */
  crypto_digest256(digest, microdesc, strlen(microdesc), DIGEST_SHA256);
  base64_encode_nopad(digest_base64, sizeof(digest_base64), (uint8_t *) digest, DIGEST256_LEN);

  mc = get_microdesc_cache();
  list = microdescs_add_to_cache(mc, microdesc, NULL, SAVED_NOWHERE, 0,
                                  time(NULL), NULL);
  tt_int_op(1, OP_EQ, smartlist_len(list));


  /* Make the request */
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  sprintf(path, MICRODESC_GET("%s"), digest_base64);
  tt_int_op(directory_handle_command_get(conn, path, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(microdesc)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  tt_int_op(body_used, OP_EQ, strlen(body));
  tt_str_op(body, OP_EQ, microdesc);

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);

    if (mock_options)
      tor_free(mock_options->DataDirectory);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
    smartlist_free(list);
    microdesc_free_all();
}

static void
test_dir_handle_get_micro_d_server_busy(void *data)
{
  dir_connection_t *conn = NULL;
  microdesc_cache_t *mc = NULL ;
  smartlist_t *list = NULL;
  char digest[DIGEST256_LEN];
  char digest_base64[128];
  char path[80];
  char *header = NULL;
  (void) data;

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  init_mock_options();
  mock_options->DataDirectory = tor_strdup(get_fname("dir_handle_datadir_test2"));

#ifdef _WIN32
  tt_int_op(0, OP_EQ, mkdir(mock_options->DataDirectory));
#else
  tt_int_op(0, OP_EQ, mkdir(mock_options->DataDirectory, 0700));
#endif

  /* Add microdesc to cache */
  crypto_digest256(digest, microdesc, strlen(microdesc), DIGEST_SHA256);
  base64_encode_nopad(digest_base64, sizeof(digest_base64), (uint8_t *) digest, DIGEST256_LEN);

  mc = get_microdesc_cache();
  list = microdescs_add_to_cache(mc, microdesc, NULL, SAVED_NOWHERE, 0,
                                  time(NULL), NULL);
  tt_int_op(1, OP_EQ, smartlist_len(list));

  //Make it busy
  mock_options->CountPrivateBandwidth = 1;

  /* Make the request */
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  sprintf(path, MICRODESC_GET("%s"), digest_base64);
  tt_int_op(directory_handle_command_get(conn, path, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(SERVER_BUSY, OP_EQ, header);

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);

    if (mock_options)
      tor_free(mock_options->DataDirectory);

    tor_free(conn);
    tor_free(header);
    smartlist_free(list);
    microdesc_free_all();
}

#define BRIDGES_PATH "/tor/networkstatus-bridges"
static void
test_dir_handle_get_networkstatus_bridges_bad_header(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  init_mock_options();
  mock_options->BridgeAuthoritativeDir = 1;
  mock_options->BridgePassword_AuthDigest_ = "digest";
 
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  TO_CONN(conn)->linked = 1;

  tt_int_op(directory_handle_command_get(conn, GET(BRIDGES_PATH), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_options);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_networkstatus_bridges_basic_auth(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  init_mock_options();
  mock_options->BridgeAuthoritativeDir = 1;
  mock_options->BridgePassword_AuthDigest_ = tor_malloc(DIGEST256_LEN);
  crypto_digest256(mock_options->BridgePassword_AuthDigest_,
                     "abcdefghijklm12345", 18, DIGEST_SHA256);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  TO_CONN(conn)->linked = 1;

  const char *req_header = "GET " BRIDGES_PATH " HTTP/1.0\r\nAuthorization: Basic abcdefghijklm12345\r\n\r\n";
  tt_int_op(directory_handle_command_get(conn, req_header, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 0\r\n"));

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_options);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_networkstatus_bridges_different_digest(void *data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* SETUP */
  init_mock_options();
  mock_options->BridgeAuthoritativeDir = 1;
  mock_options->BridgePassword_AuthDigest_ = tor_malloc(DIGEST256_LEN);
  crypto_digest256(mock_options->BridgePassword_AuthDigest_,
                     "abcdefghijklm12345", 18, DIGEST_SHA256);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  TO_CONN(conn)->linked = 1;

  const char *req_header = "GET " BRIDGES_PATH " HTTP/1.0\r\nAuthorization: Basic NOTSAMEDIGEST\r\n\r\n";
  tt_int_op(directory_handle_command_get(conn, req_header, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_options);
    tor_free(conn);
    tor_free(header);
}

#define SERVER_DESC_GET(id) GET("/tor/server/" id)
static void
test_dir_handle_get_server_descriptors_invalid_req(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, SERVER_DESC_GET("invalid"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_str_op(header, OP_EQ, NOT_FOUND);
  tt_int_op(conn->dir_spool_src, OP_EQ, DIR_SPOOL_SERVER_BY_FP);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_options);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_server_descriptors_all(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  //TODO: change to router_get_my_extrainfo when testing "extra" path
  NS_MOCK(router_get_my_routerinfo);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* Setup fake routerlist. */
  helper_setup_fake_routerlist();

  // We are one of the routers
  routerlist_t *our_routerlist = router_get_routerlist();
  tt_int_op(smartlist_len(our_routerlist->routers), OP_GE, 1);
  mock_routerinfo = smartlist_get(our_routerlist->routers, 0);
  set_server_identity_key(mock_routerinfo->identity_pkey);

  /* Treat "all" requests as if they were unencrypted */
  mock_routerinfo->cache_info.send_unencrypted = 1;

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, SERVER_DESC_GET("all"), NULL, 0), OP_EQ, 0);

  //TODO: Is this a BUG?
  //It requires strlen(signed_descriptor_len)+1 as body_len but returns a body which
  //is smaller than that by annotation_len bytes
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, mock_routerinfo->cache_info.signed_descriptor_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  //TODO: Is this a BUG?
  //This is what should be expected:
  //tt_int_op(body_used, OP_EQ, strlen(body));
  tt_int_op(body_used, OP_EQ, mock_routerinfo->cache_info.signed_descriptor_len);

  tt_str_op(body, OP_EQ, mock_routerinfo->cache_info.signed_descriptor_body + mock_routerinfo->cache_info.annotations_len);
  tt_int_op(conn->dir_spool_src, OP_EQ, DIR_SPOOL_NONE);

  done:
    NS_UNMOCK(router_get_my_routerinfo);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);

    routerlist_free_all();
    nodelist_free_all();
    entry_guards_free_all();
}

static char
TEST_DESCRIPTOR[] =
"@uploaded-at 2014-06-08 19:20:11\n"
"@source \"127.0.0.1\"\n"
"router test000a 127.0.0.1 5000 0 7000\n"
"platform Tor 0.2.5.3-alpha-dev on Linux\n"
"protocols Link 1 2 Circuit 1\n"
"published 2014-06-08 19:20:11\n"
"fingerprint C7E7 CCB8 179F 8CC3 7F5C 8A04 2B3A 180B 934B 14BA\n"
"uptime 0\n"
"bandwidth 1073741824 1073741824 0\n"
"extra-info-digest 67A152A4C7686FB07664F872620635F194D76D95\n"
"caches-extra-info\n"
"onion-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAOuBUIEBARMkkka/TGyaQNgUEDLP0KG7sy6KNQTNOlZHUresPr/vlVjo\n"
"HPpLMfu9M2z18c51YX/muWwY9x4MyQooD56wI4+AqXQcJRwQfQlPn3Ay82uZViA9\n"
"DpBajRieLlKKkl145KjArpD7F5BVsqccvjErgFYXvhhjSrx7BVLnAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"signing-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAN6NLnSxWQnFXxqZi5D3b0BMgV6y9NJLGjYQVP+eWtPZWgqyv4zeYsqv\n"
"O9y6c5lvxyUxmNHfoAbe/s8f2Vf3/YaC17asAVSln4ktrr3e9iY74a9RMWHv1Gzk\n"
"3042nMcqj3PEhRN0PoLkcOZNjjmNbaqki6qy9bWWZDNTdo+uI44dAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"hidden-service-dir\n"
"contact auth0@test.test\n"
"ntor-onion-key pK4bs08ERYN591jj7ca17Rn9Q02TIEfhnjR6hSq+fhU=\n"
"reject *:*\n"
"router-signature\n"
"-----BEGIN SIGNATURE-----\n"
"rx88DuM3Y7tODlHNDDEVzKpwh3csaG1or+T4l2Xs1oq3iHHyPEtB6QTLYrC60trG\n"
"aAPsj3DEowGfjga1b248g2dtic8Ab+0exfjMm1RHXfDam5TXXZU3A0wMyoHjqHuf\n"
"eChGPgFNUvEc+5YtD27qEDcUjcinYztTs7/dzxBT4PE=\n"
"-----END SIGNATURE-----\n";


static void
test_dir_handle_get_server_descriptors_authority(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  crypto_pk_t *identity_pkey = pk_generate(0);
  (void) data;

  NS_MOCK(router_get_my_routerinfo);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  router_get_my_routerinfo(); //init mock
  crypto_pk_get_digest(identity_pkey, mock_routerinfo->cache_info.identity_digest);

  // the digest is mine (the channel is unnecrypted, so we must allow sending)
  set_server_identity_key(identity_pkey);
  mock_routerinfo->cache_info.send_unencrypted = 1;

  /* Setup descriptor */
  int annotation_len = strstr(TEST_DESCRIPTOR, "router ") - TEST_DESCRIPTOR;
  mock_routerinfo->cache_info.signed_descriptor_body = TEST_DESCRIPTOR;
  mock_routerinfo->cache_info.signed_descriptor_len = strlen(TEST_DESCRIPTOR);
  mock_routerinfo->cache_info.annotations_len = annotation_len;

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, SERVER_DESC_GET("authority"), NULL, 0), OP_EQ, 0);

  //TODO: Is this a BUG?
  //It requires strlen(TEST_DESCRIPTOR)+1 as body_len but returns a body which
  //is smaller than that by annotation_len bytes
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_DESCRIPTOR)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  //TODO: Is this a BUG?
  //This is what should be expected:
  //tt_int_op(body_used, OP_EQ, strlen(body));
  tt_int_op(body_used, OP_EQ, strlen(TEST_DESCRIPTOR));

  tt_str_op(body, OP_EQ, TEST_DESCRIPTOR + annotation_len);
  tt_int_op(conn->dir_spool_src, OP_EQ, DIR_SPOOL_NONE);

  done:
    NS_UNMOCK(router_get_my_routerinfo);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_routerinfo);
    tor_free(conn);
    tor_free(header);
    crypto_pk_free(identity_pkey);
}

static void
test_dir_handle_get_server_descriptors_fp(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  crypto_pk_t *identity_pkey = pk_generate(0);
  (void) data;

  NS_MOCK(router_get_my_routerinfo);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  router_get_my_routerinfo(); //init mock
  crypto_pk_get_digest(identity_pkey, mock_routerinfo->cache_info.identity_digest);

  // the digest is mine (the channel is unnecrypted, so we must allow sending)
  set_server_identity_key(identity_pkey);
  mock_routerinfo->cache_info.send_unencrypted = 1;

  /* Setup descriptor */
  int annotation_len = strstr(TEST_DESCRIPTOR, "router ") - TEST_DESCRIPTOR;
  mock_routerinfo->cache_info.signed_descriptor_body = TEST_DESCRIPTOR;
  mock_routerinfo->cache_info.signed_descriptor_len = strlen(TEST_DESCRIPTOR);
  mock_routerinfo->cache_info.annotations_len = annotation_len;

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  #define HEX1 "Fe0daff89127389bc67558691231234551193EEE"
  #define HEX2 "Deadbeef99999991111119999911111111f00ba4"
  const char *hex_digest = hex_str(mock_routerinfo->cache_info.identity_digest, DIGEST_LEN);
  char req_header[155];
  sprintf(req_header, SERVER_DESC_GET("fp/%s+" HEX1 "+" HEX2), hex_digest);
  tt_int_op(directory_handle_command_get(conn, req_header, NULL, 0), OP_EQ, 0);

  //TODO: Is this a BUG?
  //It requires strlen(TEST_DESCRIPTOR)+1 as body_len but returns a body which
  //is smaller than that by annotation_len bytes
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_DESCRIPTOR)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  //TODO: Is this a BUG?
  //This is what should be expected:
  //tt_int_op(body_used, OP_EQ, strlen(body));
  tt_int_op(body_used, OP_EQ, strlen(TEST_DESCRIPTOR));

  tt_str_op(body, OP_EQ, TEST_DESCRIPTOR + annotation_len);
  tt_int_op(conn->dir_spool_src, OP_EQ, DIR_SPOOL_NONE);

  done:
    NS_UNMOCK(router_get_my_routerinfo);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_routerinfo);
    tor_free(conn);
    tor_free(header);
    crypto_pk_free(identity_pkey);
}

static void
test_dir_handle_get_server_descriptors_d(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  crypto_pk_t *identity_pkey = pk_generate(0);
  (void) data;

  NS_MOCK(router_get_my_routerinfo);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* Setup fake routerlist. */
  helper_setup_fake_routerlist();

  /* Get one router's signed_descriptor_digest */
  routerlist_t *our_routerlist = router_get_routerlist();
  tt_int_op(smartlist_len(our_routerlist->routers), OP_GE, 1);
  routerinfo_t *router = smartlist_get(our_routerlist->routers, 0);
  const char *hex_digest = hex_str(router->cache_info.signed_descriptor_digest, DIGEST_LEN);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  #define HEX1 "Fe0daff89127389bc67558691231234551193EEE"
  #define HEX2 "Deadbeef99999991111119999911111111f00ba4"
  char req_header[155];
  sprintf(req_header, SERVER_DESC_GET("d/%s+" HEX1 "+" HEX2), hex_digest);
  tt_int_op(directory_handle_command_get(conn, req_header, NULL, 0), OP_EQ, 0);

  //TODO: Is this a BUG?
  //It requires strlen(signed_descriptor_len)+1 as body_len but returns a body which
  //is smaller than that by annotation_len bytes
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, router->cache_info.signed_descriptor_len+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));

  //TODO: Is this a BUG?
  //This is what should be expected:
  //tt_int_op(body_used, OP_EQ, strlen(body));
  tt_int_op(body_used, OP_EQ, router->cache_info.signed_descriptor_len);

  tt_str_op(body, OP_EQ, router->cache_info.signed_descriptor_body + router->cache_info.annotations_len);
  tt_int_op(conn->dir_spool_src, OP_EQ, DIR_SPOOL_NONE);

  done:
    NS_UNMOCK(router_get_my_routerinfo);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(mock_routerinfo);
    tor_free(conn);
    tor_free(header);
    crypto_pk_free(identity_pkey);
}

static void
test_dir_handle_get_server_keys_bad_req(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(BAD_REQUEST, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_server_keys_all_not_found(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/all"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(NOT_FOUND, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

#define TEST_CERTIFICATE AUTHORITY_CERT_3
#define TEST_SIGNING_KEY AUTHORITY_SIGNKEY_A_DIGEST
extern const char AUTHORITY_CERT_3[];
extern const char AUTHORITY_SIGNKEY_A_DIGEST[];

static const char TEST_CERT_IDENT_KEY[] =
  "D867ACF56A9D229B35C25F0090BC9867E906BE69"; 

static void
test_dir_handle_get_server_keys_all(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;

  dir_server_t *ds = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  clear_dir_servers();

  /* create a trusted ds */
  ds = trusted_dir_server_new("ds", "127.0.0.1", 9059, 9060, "", NULL, V3_DIRINFO, 1.0);
  tt_assert(ds);
  dir_server_add(ds);

  /* ds v3_identity_digest is the certificate's identity_key */
  base16_decode(ds->v3_identity_digest, DIGEST_LEN, TEST_CERT_IDENT_KEY, HEX_DIGEST_LEN);
  tt_int_op(0, OP_EQ, trusted_dirs_load_certs_from_string(TEST_CERTIFICATE,
    TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST, 1));

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/all"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_CERTIFICATE)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 1883\r\n"));

  tt_str_op(TEST_CERTIFICATE, OP_EQ, body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);

    clear_dir_servers();
}

static void
test_dir_handle_get_server_keys_authority_not_found(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/authority"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(NOT_FOUND, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static authority_cert_t * mock_cert = NULL;

static authority_cert_t *
get_my_v3_authority_cert_m(void)
{
  tor_assert(mock_cert);
  return mock_cert;
}

static void
test_dir_handle_get_server_keys_authority(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  mock_cert = authority_cert_parse_from_string(TEST_CERTIFICATE, NULL);

  MOCK(get_my_v3_authority_cert, get_my_v3_authority_cert_m);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/authority"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_CERTIFICATE)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 1883\r\n"));

  tt_str_op(TEST_CERTIFICATE, OP_EQ, body);

  done:
    UNMOCK(get_my_v3_authority_cert);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
    tor_free(mock_cert);
}

static void
test_dir_handle_get_server_keys_fp_not_found(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/fp/somehex"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(NOT_FOUND, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_server_keys_fp(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  tt_int_op(0, OP_EQ, trusted_dirs_load_certs_from_string(TEST_CERTIFICATE,
    TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST, 1));

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  char req[71];
  sprintf(req, GET("/tor/keys/fp/%s"), TEST_CERT_IDENT_KEY);
  tt_int_op(directory_handle_command_get(conn, req, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_CERTIFICATE)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 1883\r\n"));

  tt_str_op(TEST_CERTIFICATE, OP_EQ, body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_server_keys_sk_not_found(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/sk/somehex"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(NOT_FOUND, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_server_keys_sk(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  mock_cert = authority_cert_parse_from_string(TEST_CERTIFICATE, NULL);
  MOCK(get_my_v3_authority_cert, get_my_v3_authority_cert_m);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  tt_int_op(0, OP_EQ, trusted_dirs_load_certs_from_string(TEST_CERTIFICATE,
    TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST, 1));

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  char req[71];
  sprintf(req, GET("/tor/keys/sk/%s"), TEST_SIGNING_KEY);
  tt_int_op(directory_handle_command_get(conn, req, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_CERTIFICATE)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 1883\r\n"));

  tt_str_op(TEST_CERTIFICATE, OP_EQ, body);

  done:
    UNMOCK(get_my_v3_authority_cert);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_server_keys_fpsk_not_found(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, GET("/tor/keys/fp-sk/somehex"), NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(NOT_FOUND, OP_EQ, header);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_server_keys_fpsk(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  dir_server_t *ds = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  clear_dir_servers();

  /* create a trusted ds */
  ds = trusted_dir_server_new("ds", "127.0.0.1", 9059, 9060, "", NULL, V3_DIRINFO, 1.0);
  tt_assert(ds);

  /* ds v3_identity_digest is the certificate's identity_key */
  base16_decode(ds->v3_identity_digest, DIGEST_LEN, TEST_CERT_IDENT_KEY, HEX_DIGEST_LEN);
  dir_server_add(ds);

  tt_int_op(0, OP_EQ, trusted_dirs_load_certs_from_string(TEST_CERTIFICATE,
    TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST, 1));

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  char req[115];
  sprintf(req, GET("/tor/keys/fp-sk/%s-%s"), TEST_CERT_IDENT_KEY, TEST_SIGNING_KEY);
  tt_int_op(directory_handle_command_get(conn, req, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, strlen(TEST_CERTIFICATE)+1, 0);

  tt_assert(header);
  tt_assert(body);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 1883\r\n"));

  tt_str_op(TEST_CERTIFICATE, OP_EQ, body);

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
    clear_dir_servers();
}

static void
test_dir_handle_get_server_keys_busy(void* data)
{
  dir_connection_t *conn = NULL;
  char *header = NULL;
  (void) data;

  tt_int_op(0, OP_EQ, trusted_dirs_load_certs_from_string(TEST_CERTIFICATE,
    TRUSTED_DIRS_CERTS_SRC_DL_BY_ID_DIGEST, 1));

  MOCK(get_options, mock_get_options);
  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  /* setup busy server */
  init_mock_options();
  mock_options->CountPrivateBandwidth = 1;

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  char req[71];
  sprintf(req, GET("/tor/keys/fp/%s"), TEST_CERT_IDENT_KEY);
  tt_int_op(directory_handle_command_get(conn, req, NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1, 0);

  tt_assert(header);
  tt_str_op(SERVER_BUSY, OP_EQ, header);

  done:
    UNMOCK(get_options);
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(mock_options);
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
  DIR_HANDLE_CMD(micro_d_missing_fingerprints, 0),
  DIR_HANDLE_CMD(micro_d_finds_fingerprints, 0),
  DIR_HANDLE_CMD(micro_d_server_busy, 0),
  DIR_HANDLE_CMD(networkstatus_bridges_bad_header, 0),
  DIR_HANDLE_CMD(networkstatus_bridges_basic_auth, 0),
  DIR_HANDLE_CMD(networkstatus_bridges_different_digest, 0),
  DIR_HANDLE_CMD(server_descriptors_invalid_req, 0),
  DIR_HANDLE_CMD(server_descriptors_all, TT_FORK),
  DIR_HANDLE_CMD(server_descriptors_authority, TT_FORK),
  DIR_HANDLE_CMD(server_descriptors_fp, TT_FORK),
  DIR_HANDLE_CMD(server_descriptors_d, TT_FORK),
  DIR_HANDLE_CMD(server_keys_bad_req, 0),
  DIR_HANDLE_CMD(server_keys_all_not_found, 0),
  DIR_HANDLE_CMD(server_keys_all, 0),
  DIR_HANDLE_CMD(server_keys_authority_not_found, 0),
  DIR_HANDLE_CMD(server_keys_authority, 0),
  DIR_HANDLE_CMD(server_keys_fp_not_found, 0),
  DIR_HANDLE_CMD(server_keys_fp, 0),
  DIR_HANDLE_CMD(server_keys_sk_not_found, 0),
  DIR_HANDLE_CMD(server_keys_sk, 0),
  DIR_HANDLE_CMD(server_keys_fpsk_not_found, 0),
  DIR_HANDLE_CMD(server_keys_fpsk, 0),
  DIR_HANDLE_CMD(server_keys_busy, 0),
  END_OF_TESTCASES
};
