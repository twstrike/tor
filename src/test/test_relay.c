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
#include "config.h"

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

typedef struct relay_connection_test_data_t {
  cell_t *cell;
  circuit_t *circ;
  relay_header_t *rh;
  entry_connection_t *entryconn;
  edge_connection_t *edgeconn;
  crypt_path_t *layer_hint;
  crypt_path_t *cpath1;
  crypt_path_t *cpath2;
  channel_tls_t *p_chan;
  or_circuit_t *or_circ;
} relay_connection_test_data_t;

const char *
fake_get_remote_descr(channel_t *conn, int flags)
{
  return "127.0.0.1";
}

static relay_connection_test_data_t *
init_relay_connection_test_data()
{
  char iv[CIPHER_IV_LEN];
  crypto_rand(iv, CIPHER_IV_LEN);
  relay_connection_test_data_t *result = tor_malloc_zero(sizeof(relay_connection_test_data_t));

  result->entryconn = entry_connection_new(CONN_TYPE_AP, AF_INET);
  result->edgeconn = ENTRY_TO_EDGE_CONN(result->entryconn);
  result->edgeconn->base_.magic = EDGE_CONNECTION_MAGIC;
  result->edgeconn->base_.purpose = EXIT_PURPOSE_CONNECT;

  result->rh = tor_malloc_zero(sizeof(relay_header_t));
  result->rh->command = RELAY_COMMAND_BEGIN;
  result->rh->stream_id = 2;
  result->rh->length = 100;
  result->rh->recognized = 0;

  result->cell = tor_malloc_zero(sizeof(cell_t));
  result->cell->circ_id = 1;
  result->cell->command = CELL_RELAY;
  memset(result->cell->payload, 0, CELL_PAYLOAD_SIZE);
  relay_header_pack(result->cell->payload, result->rh);

  crypto_digest_t *digest = crypto_digest_new();
  char integrity[4];

  crypto_digest_add_bytes(digest, (char*)result->cell->payload, CELL_PAYLOAD_SIZE);
  crypto_digest_get_digest(digest, integrity, 4);
  memcpy(result->rh->integrity, integrity, 4);
  relay_header_pack(result->cell->payload, result->rh);

  result->cpath1 = tor_malloc(sizeof(crypt_path_t));
  result->cpath2 = tor_malloc(sizeof(crypt_path_t));

  result->cpath1->magic = CRYPT_PATH_MAGIC;
  result->cpath1->f_crypto = crypto_cipher_new(NULL);
  result->cpath1->b_crypto = crypto_cipher_new_with_iv(NULL, iv);
  result->cpath1->f_digest = crypto_digest_new();
  result->cpath1->b_digest = crypto_digest_new();
  result->cpath1->state = CPATH_STATE_OPEN;

  result->cpath2->magic = CRYPT_PATH_MAGIC;
  result->cpath2->f_crypto = crypto_cipher_new(NULL);
  result->cpath2->b_crypto = crypto_cipher_new(NULL);
  result->cpath2->f_digest = crypto_digest_new();
  result->cpath2->b_digest = crypto_digest_new();
  result->cpath2->state = CPATH_STATE_OPEN;

  result->cpath1->next = result->cpath2;
  result->cpath2->next = result->cpath1;

  result->cpath1->prev = result->cpath2;
  result->cpath2->prev = result->cpath1;

  result->or_circ = tor_malloc_zero(sizeof(or_circuit_t));
  result->or_circ->base_.magic = OR_CIRCUIT_MAGIC;
  result->or_circ->base_.purpose = CIRCUIT_PURPOSE_OR;
  result->or_circ->p_crypto = crypto_cipher_new(NULL);
  result->or_circ->n_crypto = crypto_cipher_new(NULL);
  result->or_circ->p_digest = crypto_digest_new();
  result->or_circ->n_digest = crypto_digest_new();
  result->p_chan = tor_malloc_zero(sizeof(channel_tls_t));
  result->p_chan->base_.get_remote_descr = fake_get_remote_descr;
  result->p_chan->base_.global_identifier = 2;
  result->or_circ->p_chan = &(result->p_chan->base_);
  result->circ = TO_CIRCUIT(result->or_circ);
  result->circ->magic = ORIGIN_CIRCUIT_MAGIC;
  result->circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  TO_ORIGIN_CIRCUIT(result->circ)->cpath = result->cpath1;
  char recognized = 0;
  crypto_cipher_t *local_b_crypt = crypto_cipher_new_with_iv(crypto_cipher_get_key(result->cpath1->b_crypto), iv);
  relay_crypt_one_payload(local_b_crypt, result->cell->payload, 1);
  relay_crypt(result->circ, result->cell, CELL_DIRECTION_IN, &result->layer_hint, &recognized);
  return result;
}


static void
clean_relay_connection_test_data(relay_connection_test_data_t *data)
{
  tor_free(data->cell);
  tor_free(data->circ);
  tor_free(data->rh);
  tor_free(data->entryconn);
  tor_free(data->cpath1);
  tor_free(data->cpath2);
  tor_free(data->p_chan);
  tor_free(data);
}

static void
test_relay_connection_edge_process_relay_cell__cell_length_too_long(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->length = RELAY_PAYLOAD_SIZE + 1;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__no_stream_id_with_relay_that_needs_stream(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->stream_id = 0;
  tdata->rh->command = RELAY_COMMAND_BEGIN;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_CONNECTED;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_END;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_RESOLVE;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_RESOLVED;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_BEGIN_DIR;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->rh->command = RELAY_COMMAND_INTRODUCE_ACK;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__closed_connection(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->edgeconn->base_.type = CONN_TYPE_EXIT;
  tdata->edgeconn->base_.state = EXIT_CONN_STATE_CONNECTING;
  tdata->rh->stream_id = 0;
  tdata->rh->command = RELAY_COMMAND_DATA;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

  tdata->edgeconn->base_.state = EXIT_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

  tdata->edgeconn->base_.state = EXIT_CONN_STATE_CONNECTING;
  tdata->rh->command = RELAY_COMMAND_INTRODUCE_ACK;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->edgeconn->base_.type = CONN_TYPE_AP;
  tdata->rh->stream_id = 1;
  tdata->rh->command = RELAY_COMMAND_DATA;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__open_connection(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();
  tdata->edgeconn->base_.magic = OR_CONNECTION_MAGIC;
  tdata->edgeconn->base_.purpose = 0;
  tdata->edgeconn->base_.address = tor_strdup("127.0.0.1");

  tdata->rh->stream_id = 1;
  tdata->rh->command = RELAY_COMMAND_DATA;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -1);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__command_group(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_DROP;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  clean_relay_connection_test_data(tdata);
}

static int
mocked_relay_send_command_from_edge_(streamid_t stream_id, circuit_t *circ,
                                     uint8_t relay_command, const char *payload,
                                     size_t payload_len, crypt_path_t *cpath_layer,
                                     const char *filename, int lineno)
{
  return 99;
}

static void mocked_circuit_mark_for_close_(circuit_t *circ, int reason, int line,
                                           const char *file)
{
}


static void
test_relay_connection_edge_process_relay_cell__begin(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  MOCK(relay_send_command_from_edge_, mocked_relay_send_command_from_edge_);
  tdata->rh->command = RELAY_COMMAND_BEGIN;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->magic = OR_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_OR;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->magic = ORIGIN_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  TO_ORIGIN_CIRCUIT(tdata->circ)->cpath->prev = tdata->layer_hint;
  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, tdata->layer_hint);
  TO_ORIGIN_CIRCUIT(tdata->circ)->cpath->prev = tdata->cpath2;
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->magic = OR_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  UNMOCK(relay_send_command_from_edge_);
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__begin_dir(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_BEGIN_DIR;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  MOCK(relay_send_command_from_edge_, mocked_relay_send_command_from_edge_);
  tdata->circ->magic = OR_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_OR;
  int id_before = tdata->circ->dirreq_id;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(tdata->circ->dirreq_id, OP_GT, id_before);
  tt_int_op(tdata->circ->dirreq_id, OP_EQ, tdata->or_circ->p_chan->dirreq_id);

  tdata->circ->magic = ORIGIN_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;
  TO_ORIGIN_CIRCUIT(tdata->circ)->cpath->prev = tdata->layer_hint;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, tdata->layer_hint);
  TO_ORIGIN_CIRCUIT(tdata->circ)->cpath->prev = tdata->cpath2;
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->magic = OR_CIRCUIT_MAGIC;
  tdata->circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  UNMOCK(relay_send_command_from_edge_);
  clean_relay_connection_test_data(tdata);
}


static void
test_relay_connection_edge_process_relay_cell__resolved(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_RESOLVED;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__resolve(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_RESOLVE;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, 0);

  tdata->circ->purpose = CIRCUIT_PURPOSE_S_INTRO;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  MOCK(relay_send_command_from_edge_, mocked_relay_send_command_from_edge_);
  tdata->circ->purpose = CIRCUIT_PURPOSE_OR;
  tdata->circ->magic = OR_CIRCUIT_MAGIC;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  UNMOCK(relay_send_command_from_edge_);
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__connected(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_CONNECTED;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  tdata->edgeconn->base_.marked_for_close = 0;
  tdata->edgeconn->base_.type = CONN_TYPE_OR;
  tdata->edgeconn->base_.state = OR_CONN_STATE_OPEN;
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, tdata->edgeconn, NULL);
  tt_int_op(ret, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  clean_relay_connection_test_data(tdata);
}

static void
test_relay_connection_edge_process_relay_cell__truncated(void *ignored)
{
  (void)ignored;
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = RELAY_COMMAND_TRUNCATED;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

  MOCK(circuit_mark_for_close_, mocked_circuit_mark_for_close_);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, tdata->layer_hint);
  tt_int_op(ret, OP_EQ, 0);

 done:
  UNMOCK(circuit_mark_for_close_);
  clean_relay_connection_test_data(tdata);
}


typedef struct command_type_holder_t {
  uint8_t command;
} command_type_holder_t;

void *create_command_type_holder(const struct testcase_t *testcase)
{
  command_type_holder_t *env = tor_malloc_zero(sizeof(command_type_holder_t));
  if (! env)
    return NULL;
  env->command = (intptr_t)testcase->setup_data;
  return env;
}

int cleanup_command_type_holder(const struct testcase_t *tc, void *env_)
{
  command_type_holder_t *env = env_;
  tor_free(env);
  return 1;
}

struct testcase_setup_t env_setup = {
  create_command_type_holder,
  cleanup_command_type_holder
};


static void
test_relay_connection_edge_process_relay_cell__command(void *command_type)
{
  int ret;
  init_connection_lists();
  relay_connection_test_data_t *tdata = init_relay_connection_test_data();

  tdata->rh->command = ((command_type_holder_t *)command_type)->command;
  relay_header_pack(tdata->cell->payload, tdata->rh);
  ret = connection_edge_process_relay_cell(tdata->cell, tdata->circ, NULL, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  clean_relay_connection_test_data(tdata);
}

#define RELAY_TEST(name, flags)                     \
  { #name, test_relay_ ## name, flags, NULL, NULL }

#define RELAY_COMMAND_TEST(name, flags, value)            \
  { "connection_edge_process_relay_cell__" #name, test_relay_connection_edge_process_relay_cell__command, flags, &env_setup, (void *) value }

struct testcase_t relay_tests[] = {
  RELAY_TEST(append_cell_to_circuit_queue, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__cell_length_too_long, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__no_stream_id_with_relay_that_needs_stream, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__closed_connection, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__open_connection, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__command_group, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__begin, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__begin_dir, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__resolved, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__resolve, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__connected, TT_FORK),
  RELAY_TEST(connection_edge_process_relay_cell__truncated, TT_FORK),
  RELAY_COMMAND_TEST(establish_intro, TT_FORK, RELAY_COMMAND_ESTABLISH_INTRO),
  RELAY_COMMAND_TEST(establish_rendezvous, TT_FORK, RELAY_COMMAND_ESTABLISH_RENDEZVOUS),
  RELAY_COMMAND_TEST(introduce1, TT_FORK, RELAY_COMMAND_INTRODUCE1),
  RELAY_COMMAND_TEST(introduce2, TT_FORK, RELAY_COMMAND_INTRODUCE2),
  RELAY_COMMAND_TEST(rendezvous1, TT_FORK, RELAY_COMMAND_RENDEZVOUS1),
  RELAY_COMMAND_TEST(rendezvous2, TT_FORK, RELAY_COMMAND_RENDEZVOUS2),
  RELAY_COMMAND_TEST(intro_established, TT_FORK, RELAY_COMMAND_INTRO_ESTABLISHED),
  RELAY_COMMAND_TEST(rendezvous_established, TT_FORK, RELAY_COMMAND_RENDEZVOUS_ESTABLISHED),
  RELAY_COMMAND_TEST(unknown_command, TT_FORK, 99),
  END_OF_TESTCASES
};
