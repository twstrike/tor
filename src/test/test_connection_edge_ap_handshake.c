/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONNECTION_PRIVATE
#define CONNECTION_EDGE_PRIVATE
#define ROUTERSET_PRIVATE
#define LOG_PRIVATE

#include "or.h"
#include "config.h"
#include "connection.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "addressmap.h"
#include "nodelist.h"
#include "routerset.h"
#include "util.h"
#include "torlog.h"
#include "test.h"
#include "log_test_helpers.h"

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
init_rewrite_mock()
{
  MOCK(connection_ap_handshake_rewrite, connection_ap_handshake_rewrite_mock);
  rewrite_mock = tor_malloc_zero(sizeof(rewrite_result_t));
}
static void
destroy_rewrite_mock()
{
  UNMOCK(connection_ap_handshake_rewrite);
}

static int unattachment_reason_spy;
static void
connection_mark_unattached_ap_mock(entry_connection_t *conn,
                                     int reason,
                                     int line,
                                     const char *file)
{
  tor_assert(reason);
  unattachment_reason_spy = reason;
  (void) conn;
  (void) line;
  (void) file;
}
static void
init_mark_unattached_ap_mock()
{
  MOCK(connection_mark_unattached_ap_, connection_mark_unattached_ap_mock);
}
static void
destroy_mark_unattached_ap_mock()
{
  UNMOCK(connection_mark_unattached_ap_);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_with_answer(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 1;
  rewrite_mock->end_reason = END_STREAM_REASON_DONE;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, 0);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
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

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 1;
  rewrite_mock->end_reason = END_STREAM_REASON_MISC;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    tor_free(rewrite_mock);
    tor_free(circuit); 
    tor_free(path); 
}

#define SET_SOCKS_ADDRESS(socks, dest) \
  strlcpy(socks->address, dest, sizeof(socks->address));

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_hostname_is_bogus(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.bogus.onion");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
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

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_AUTOMAP;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.notgood.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
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

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_DNS;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.dns.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
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

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.notremapped.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

static or_options_t *options_mock = NULL;
static const or_options_t *
get_options_mock(void)
{
  tor_assert(options_mock);
  return options_mock;
}
static void
init_mock_options()
{
  options_mock = tor_malloc_zero(sizeof(options_mock));
  MOCK(get_options, get_options_mock);
}
static void
destroy_mock_options()
{
  tor_free(options_mock);
  UNMOCK(get_options);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_is_allowed_but_malformed(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://malformed..exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  init_mock_options();
  options_mock->AllowDotExit = 1;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    destroy_mock_options();
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
    destroy_mock_options();
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_when_exit_doesnt_really_exist(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  init_mock_options();
  options_mock->AllowDotExit = 1;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    destroy_mock_options();
    tor_free(rewrite_mock);
    tor_free(circuit);
    tor_free(path);
}

static node_t *exit_node_mock = NULL;
static const node_t *
node_get_by_nickname_mock(const char *nickname, int warn)
{
  tor_assert(nickname);
  tor_assert(warn);
  return exit_node_mock;
}
static void
init_exit_node_mock()
{
  MOCK(node_get_by_nickname, node_get_by_nickname_mock);
  exit_node_mock = tor_malloc_zero(sizeof(node_t));
  exit_node_mock->rs = tor_malloc_zero(sizeof(routerstatus_t));
}
static void
destroy_exit_node_mock()
{
  UNMOCK(node_get_by_nickname);
  tor_free(exit_node_mock->rs);
  tor_free(exit_node_mock);
}

static routerset_t *excluded_nodes = NULL;

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_for_excluded_exit(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;
  int prev_log = setup_capture_of_logs(LOG_INFO);

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  init_exit_node_mock();
  init_mock_options();

  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  strlcpy(exit_node_mock->rs->nickname, "wellformed", 10);

  options_mock->AllowDotExit = 1;
  options_mock->StrictNodes = 0;
  options_mock->SafeLogging_ = SAFELOG_SCRUB_NONE;

  excluded_nodes = routerset_new();
  smartlist_add(excluded_nodes->list, "wellformed");
  strmap_set(excluded_nodes->names, "wellformed", exit_node_mock);
  options_mock->ExcludeExitNodes = excluded_nodes;

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(-1), OP_EQ, "Excluded relay in exit address 'http://www.exit'. Refusing.\n");

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    destroy_mock_options();
    destroy_exit_node_mock();
    tor_free(rewrite_mock);
    tor_free(excluded_nodes);
    tor_free(circuit);
    tor_free(path);
    teardown_capture_of_logs(prev_log);
}

static void
test_conn_edge_ap_handshake_rewrite_and_attach_closes_conn_to_port0(void *data)
{
  entry_connection_t *conn = data;
  origin_circuit_t *circuit = NULL;
  crypt_path_t *path = NULL;

  init_mark_unattached_ap_mock();
  init_rewrite_mock();
  rewrite_mock->should_close = 0;
  rewrite_mock->exit_source = ADDRMAPSRC_NONE;
  SET_SOCKS_ADDRESS(conn->socks_request, "http://www.wellformed.exit");
  conn->socks_request->command = SOCKS_COMMAND_CONNECT;
  init_mock_options();
  options_mock->AllowDotExit = 1;
  init_exit_node_mock();

  int res = connection_ap_handshake_rewrite_and_attach(conn, circuit, path);

  tt_int_op(unattachment_reason_spy, OP_EQ, END_STREAM_REASON_TORPROTOCOL);
  tt_int_op(res, OP_EQ, -1);

  done:
    destroy_mark_unattached_ap_mock();
    destroy_rewrite_mock();
    destroy_mock_options();
    destroy_exit_node_mock();
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
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_exit_is_allowed_but_malformed, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_when_exit_doesnt_really_exist, 0),
  CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_for_excluded_exit, 0),
  //CONN_EDGE_AP_HANDSHAKE(rewrite_and_attach_closes_conn_to_port0, 0),
  END_OF_TESTCASES
};
