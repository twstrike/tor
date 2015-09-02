/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONNECTION_PRIVATE
#define CONNECTION_EDGE_PRIVATE

#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "addressmap.h"
#include "util.h"
#include "test.h"

#define NS_MODULE conn_edge_ap_handshake

static void *
entryconn_rewrite_setup(const struct testcase_t *tc)
{
  (void)tc;
  entry_connection_t *ec = entry_connection_new(CONN_TYPE_AP, AF_INET);
  addressmap_init();
  return ec;
}

static int
entryconn_rewrite_teardown(const struct testcase_t *tc, void *arg)
{
  (void)tc;
  entry_connection_t *ec = arg;
  if (ec)
    connection_free_(ENTRY_TO_CONN(ec));
  addressmap_free_all();
  return 1;
}

static struct testcase_setup_t test_rewrite_setup = {
  entryconn_rewrite_setup, entryconn_rewrite_teardown
};

static rewrite_result_t *rewrite_mock = NULL; 

static void
connection_ap_handshake_rewrite_mock(entry_connection_t *conn,
                                       rewrite_result_t *result)
{
  tor_assert(result);
  result->should_close = rewrite_mock->should_close;
  result->end_reason = rewrite_mock->end_reason;
  result->exit_source = rewrite_mock->exit_source;
  (void) conn;
}

static void
connection_mark_unattached_ap_mock(entry_connection_t *conn,
                                     int reason,
                                     int line,
                                     const char *file)
{
  tor_assert(reason);
  (void) conn;
  (void) line;
  (void) file;
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_answer(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 1;
  rewrite_mock->end_reason = END_STREAM_REASON_DONE;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, 0);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit); 
    tor_free(path); 
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_error(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 1;
  rewrite_mock->end_reason = END_STREAM_REASON_MISC;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit); 
    tor_free(path); 
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_bogus(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 0;
  strlcpy(conn->socks_request->address,
            "http://www.bogus.onion",
            sizeof(conn->socks_request->address));
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_unallowed_exit(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_AUTOMAP;
  strlcpy(conn->socks_request->address,
            "http://www.notgood.exit",
            sizeof(conn->socks_request->address));
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_dns_exit(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_DNS;
  strlcpy(conn->socks_request->address,
            "http://www.dns.exit",
            sizeof(conn->socks_request->address));
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_exit_but_not_remapped(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  strlcpy(conn->socks_request->address,
            "http://www.notremapped.exit",
            sizeof(conn->socks_request->address));
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    UNMOCK(connection_ap_handshake_rewrite);
    UNMOCK(connection_mark_unattached_ap_);
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

#define CONN_EDGE_AP_HANDSHAKE(name,flags)                              \
  { #name, test_conn_edge_ap_handshake_##name, (flags), &test_rewrite_setup, NULL }

struct testcase_t conn_edge_ap_handshake_tests[] =
{
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_with_answer, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_with_error, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_bogus, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_unallowed_exit, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_dns_exit, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_hostname_is_exit_but_not_remapped, 0),
  END_OF_TESTCASES
};
