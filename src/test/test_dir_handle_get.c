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
  dir_connection_t *conn;
  char *sent = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, "", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &sent, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

  tt_str_op(sent, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(sent);
}

static void
test_dir_handle_get_v1_command_without_disclaimer(void *data)
{
  dir_connection_t *conn;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // no frontpage configured
  tt_ptr_op(get_dirportfrontpage(), OP_EQ, NULL);

  /* V1 path */
  tt_int_op(directory_handle_command_get(conn, "GET /tor/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

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
  dir_connection_t *conn;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  MOCK(get_dirportfrontpage, mock_get_dirportfrontpage);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));
  tt_int_op(directory_handle_command_get(conn, "GET /tor/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);

  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, 1000, 0);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/html\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Content-Length: 20\r\n"));

  tt_int_op(body_used, OP_EQ, 20);
  tt_str_op(body, OP_EQ, "HELLO FROM FRONTPAGE");

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
  dir_connection_t *conn;
  char *sent = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  /* Unrecognized path */
  tt_int_op(directory_handle_command_get(conn, "GET /anything HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &sent, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

  tt_str_op(sent, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(sent);
}

static void
test_dir_handle_get_robots_txt(void *data)
{
  dir_connection_t *conn;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/robots.txt HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, 1000, 0);

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
  dir_connection_t *conn;
  char *header = NULL;
  char *body = NULL;
  size_t body_used = 0;
  char buff[30];
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/bytes.txt HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      &body, &body_used, 1000, 0);

  tt_ptr_op(strstr(header, "HTTP/1.0 200 OK\r\n"), OP_EQ, header);
  tt_assert(strstr(header, "Content-Type: text/plain\r\n"));
  tt_assert(strstr(header, "Content-Encoding: identity\r\n"));
  tt_assert(strstr(header, "Pragma: no-cache\r\n"));
  
  sprintf(buff, "Content-Length: %ld\r\n", body_used);
  tt_assert(strstr(header, buff));

  tt_str_op(body, OP_EQ, directory_dump_request_log());

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    tor_free(body);
}

static void
test_dir_handle_get_rendezvous2_on_not_encrypted_conn(void *data)
{
  dir_connection_t *conn;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);

  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is not encrypted
  tt_assert(!connection_dir_is_encrypted(conn))

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/ HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_with_invalid_desc_id(void *data)
{
  dir_connection_t *conn;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/invalid-desc-id HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_not_well_formed(void *data)
{
  dir_connection_t *conn;
  char *header = NULL;
  (void) data;

  MOCK(connection_write_to_buf_impl_, connection_write_to_buf_mock);
  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  // connection is encrypted
  TO_CONN(conn)->linked = 1;
  tt_assert(connection_dir_is_encrypted(conn));

  //FIXME: this cant be reached because rend_valid_descriptor_id() prevents this
  //case to happen. This test is the same as 
  //test_dir_handle_get_rendezvous2_on_encrypted_conn_with_invalid_desc_id
  //We should refactor to remove the case from the switch.

  tt_int_op(directory_handle_command_get(conn, "GET /tor/rendezvous2/1bababababababababababababababab HTTP/1.0\r\n\r\n", NULL, 0), OP_EQ, 0);
  fetch_from_buf_http(TO_CONN(conn)->outbuf, &header, MAX_HEADERS_SIZE,
                      NULL, NULL, 1000, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 400 Bad request\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
}

static void
test_dir_handle_get_rendezvous2_on_encrypted_conn_not_present(void *data)
{
  dir_connection_t *conn;
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
                      NULL, NULL, 1000, 0);

  tt_str_op(header, OP_EQ, "HTTP/1.0 404 Not found\r\n\r\n");

  done:
    UNMOCK(connection_write_to_buf_impl_);
    tor_free(conn);
    tor_free(header);
    rend_cache_free_all();
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
  END_OF_TESTCASES
};

