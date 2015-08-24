/* Copyright (c) 2014-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#define CIRCUITBUILD_PRIVATE
#include "circuitbuild.h"
#define RELAY_PRIVATE
#include "relay.h"
#define MAIN_PRIVATE
#include "main.h"
#define TOR_CHANNEL_INTERNAL_
#include "channel.h"
#include "channeltls.h"

/* For init/free stuff */
#include "scheduler.h"
#include "connection.h"
#include "circuitlist.h"

/* Test suite stuff */
#include "test.h"
#include "fakechans.h"

static or_circuit_t * new_fake_orcirc(channel_t *nchan, channel_t *pchan);

static void test_relay_append_cell_to_circuit_queue(void *arg);

static or_circuit_t *
new_fake_orcirc(channel_t *nchan, channel_t *pchan)
{
  or_circuit_t *orcirc = NULL;
  circuit_t *circ = NULL;

  orcirc = tor_malloc_zero(sizeof(*orcirc));
  circ = &(orcirc->base_);
  circ->magic = OR_CIRCUIT_MAGIC;

  circ->n_chan = nchan;
  circ->n_circ_id = get_unique_circ_id_by_chan(nchan);
  circ->n_mux = NULL; /* ?? */
  cell_queue_init(&(circ->n_chan_cells));
  circ->n_hop = NULL;
  circ->streams_blocked_on_n_chan = 0;
  circ->streams_blocked_on_p_chan = 0;
  circ->n_delete_pending = 0;
  circ->p_delete_pending = 0;
  circ->received_destroy = 0;
  circ->state = CIRCUIT_STATE_OPEN;
  circ->purpose = CIRCUIT_PURPOSE_OR;
  circ->package_window = CIRCWINDOW_START_MAX;
  circ->deliver_window = CIRCWINDOW_START_MAX;
  circ->n_chan_create_cell = NULL;

  orcirc->p_chan = pchan;
  orcirc->p_circ_id = get_unique_circ_id_by_chan(pchan);
  cell_queue_init(&(orcirc->p_chan_cells));

  return orcirc;
}

static void
test_relay_append_cell_to_circuit_queue(void *arg)
{
  channel_t *nchan = NULL, *pchan = NULL;
  or_circuit_t *orcirc = NULL;
  cell_t *cell = NULL;
  int old_count, new_count;

  (void)arg;

  /* Make fake channels to be nchan and pchan for the circuit */
  nchan = new_fake_channel();
  tt_assert(nchan);

  pchan = new_fake_channel();
  tt_assert(pchan);

  /* We'll need chans with working cmuxes */
  nchan->cmux = circuitmux_alloc();
  pchan->cmux = circuitmux_alloc();

  /* Make a fake orcirc */
  orcirc = new_fake_orcirc(nchan, pchan);
  tt_assert(orcirc);

  /* Make a cell */
  cell = tor_malloc_zero(sizeof(cell_t));
  make_fake_cell(cell);

  MOCK(scheduler_channel_has_waiting_cells,
       scheduler_channel_has_waiting_cells_mock);

  /* Append it */
  old_count = get_mock_scheduler_has_waiting_cells_count();
  append_cell_to_circuit_queue(TO_CIRCUIT(orcirc), nchan, cell,
                               CELL_DIRECTION_OUT, 0);
  new_count = get_mock_scheduler_has_waiting_cells_count();
  tt_int_op(new_count, ==, old_count + 1);

  /* Now try the reverse direction */
  old_count = get_mock_scheduler_has_waiting_cells_count();
  append_cell_to_circuit_queue(TO_CIRCUIT(orcirc), pchan, cell,
                               CELL_DIRECTION_IN, 0);
  new_count = get_mock_scheduler_has_waiting_cells_count();
  tt_int_op(new_count, ==, old_count + 1);

  UNMOCK(scheduler_channel_has_waiting_cells);

  /* Get rid of the fake channels */
  MOCK(scheduler_release_channel, scheduler_release_channel_mock);
  channel_mark_for_close(nchan);
  channel_mark_for_close(pchan);
  UNMOCK(scheduler_release_channel);

  /* Shut down channels */
  channel_free_all();

 done:
  tor_free(cell);
  cell_queue_clear(&orcirc->base_.n_chan_cells);
  cell_queue_clear(&orcirc->p_chan_cells);
  tor_free(orcirc);
  free_fake_channel(nchan);
  free_fake_channel(pchan);

  return;
}

static void
test_relay_connection_edge_process_relay_cell(void *ignored)
{
  (void)ignored;

  int ret;
  cell_t *cell;
  circuit_t *circ;
  relay_header_t *rh;
  entry_connection_t *entryconn;
  edge_connection_t *edgeconn;
  crypt_path_t *layer_hint;
  crypt_path_t *cpath1, *cpath2;
  channel_tls_t *p_chan=NULL;

  init_connection_lists();

  entryconn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  edgeconn = ENTRY_TO_EDGE_CONN(entryconn);

  rh = tor_malloc_zero(sizeof(relay_header_t));
  rh->command = RELAY_COMMAND_BEGIN;
  rh->stream_id = 2;
  rh->length = 100;

  cpath1 = tor_malloc(sizeof(crypt_path_t));
  cpath2 = tor_malloc(sizeof(crypt_path_t));

  cpath1->magic = CRYPT_PATH_MAGIC;
  cpath1->f_crypto = crypto_cipher_new(NULL);
  cpath1->b_crypto = crypto_cipher_new(NULL);
  cpath1->f_digest = crypto_digest_new();
  cpath1->b_digest = crypto_digest_new();
  cpath1->state = CPATH_STATE_OPEN;

  cpath2->magic = CRYPT_PATH_MAGIC;
  cpath2->f_crypto = crypto_cipher_new(NULL);
  cpath2->b_crypto = crypto_cipher_new(NULL);
  cpath2->f_digest = crypto_digest_new();
  cpath2->b_digest = crypto_digest_new();
  cpath2->state = CPATH_STATE_OPEN;

  cpath1->next = cpath2;
  cpath2->next = cpath1;

  cpath1->prev = cpath2;
  cpath2->prev = cpath1;

  cell_t *cellx = tor_malloc(sizeof(cell_t));
  or_circuit_t *or_circ = tor_malloc_zero(sizeof(or_circuit_t));
  or_circ->base_.magic = OR_CIRCUIT_MAGIC;
  or_circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  or_circ->p_crypto = crypto_cipher_new(NULL);
  or_circ->n_crypto = crypto_cipher_new(NULL);
  or_circ->p_digest = crypto_digest_new();
  or_circ->n_digest = crypto_digest_new();
  p_chan = tor_malloc_zero(sizeof(channel_tls_t));
  p_chan->base_.global_identifier = 2;
  or_circ->p_chan = &(p_chan->base_);
  circ = TO_CIRCUIT(or_circ);
  TO_ORIGIN_CIRCUIT(circ)->cpath = cpath1;
  char recognized = 0;
  relay_crypt(circ, cellx, CELL_DIRECTION_IN, &layer_hint, &recognized);

  cell = tor_malloc_zero(sizeof(cell_t));
  cell->circ_id = 1;
  cell->command = CELL_RELAY;
  memset(cell->payload, 0, CELL_PAYLOAD_SIZE);
  relay_header_pack(cell->payload, rh);

  // Test returns failure if the relay cell length is too long
  rh->length = RELAY_PAYLOAD_SIZE + 1;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);
  rh->length = 10;

  // Test if stream_id is zero and the relay command needs a stream
  rh->stream_id = 0;
  rh->command = RELAY_COMMAND_BEGIN;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_CONNECTED;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_END;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_RESOLVE;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_RESOLVED;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_BEGIN_DIR;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  rh->command = RELAY_COMMAND_INTRODUCE_ACK;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  // Test a closed connection
  edgeconn->base_.type = CONN_TYPE_EXIT;
  edgeconn->base_.state = EXIT_CONN_STATE_CONNECTING;
  rh->command = RELAY_COMMAND_DATA;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

  edgeconn->base_.state = EXIT_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

  edgeconn->base_.state = EXIT_CONN_STATE_CONNECTING;
  rh->command = RELAY_COMMAND_INTRODUCE_ACK;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

  edgeconn->base_.type = CONN_TYPE_AP;
  rh->stream_id = 1;
  rh->command = RELAY_COMMAND_DATA;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

  // Test an open connection
  edgeconn->base_.marked_for_close = 0;
  edgeconn->base_.type = CONN_TYPE_OR;
  edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

  // Test relay command drop
  rh->command = RELAY_COMMAND_DROP;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  // Test relay command begin
  rh->command = RELAY_COMMAND_BEGIN;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  TO_ORIGIN_CIRCUIT(circ)->cpath->prev = layer_hint;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  TO_ORIGIN_CIRCUIT(circ)->cpath->prev = cpath2;
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  ret = connection_edge_process_relay_cell(cell, circ, edgeconn, layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  // Test relay command begin dir
  rh->command = RELAY_COMMAND_BEGIN_DIR;
  relay_header_pack(cell->payload, rh);
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  TO_ORIGIN_CIRCUIT(circ)->cpath->prev = layer_hint;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, layer_hint);
  TO_ORIGIN_CIRCUIT(circ)->cpath->prev = cpath2;
  tt_int_op(ret, OP_EQ, 0);

  circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  int id_before = circ->dirreq_id;
  ret = connection_edge_process_relay_cell(cell, circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(circ->dirreq_id, OP_GT, id_before);
  tt_int_op(circ->dirreq_id, OP_EQ, or_circ->p_chan->dirreq_id);




 done:
  tor_free(rh);
}

#define RELAY_TEST(name, flags)                     \
  { #name, test_relay_ ## name, flags, NULL, NULL }

struct testcase_t relay_tests[] = {
  RELAY_TEST(append_cell_to_circuit_queue, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell, 0),
  END_OF_TESTCASES
};
