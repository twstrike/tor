/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "test.h"

#define MAIN_PRIVATE
#include "main.h"
#include "config.h"
#include "rendcache.h"
#include "statefile.h"
#include "rephist.h"
#include "geoip.h"
#include "transports.h"

static or_state_t *mock_state = NULL;
static void
init_mock_state()
{
  mock_state = tor_malloc_zero(sizeof(or_state_t));
  mock_state->AccountingBytesReadInInterval = 0;
  mock_state->AccountingBytesWrittenInInterval = 0;
}

static or_state_t *
get_or_state_mock(void)
{
  tor_assert(mock_state);
  return mock_state;
}

static or_options_t *mock_options = NULL;
static void
init_mock_options(void){
  mock_options = malloc(sizeof(or_options_t));
  memset(mock_options, 0, sizeof(or_options_t));
  mock_options->TestingTorNetwork = 1;
}

static const or_options_t *
get_options_mock(void)
{
  tor_assert(mock_options);
  return mock_options;
}

extern STATIC time_to_t time_to;
static void
set_all_times_to(time_t now)
{
  time_to.last_rotated_x509_certificate = now;
  time_to.check_v3_certificate = now;
  time_to.check_listeners = now;
  time_to.download_networkstatus = now;
  time_to.try_getting_descriptors = now;
  time_to.reset_descriptor_failures = now;
  time_to.add_entropy = now;
  time_to.write_bridge_status_file = now;
  time_to.downrate_stability = now;
  time_to.save_stability = now;
  time_to.clean_caches = now;
  time_to.recheck_bandwidth = now;
  time_to.check_for_expired_networkstatus = now;
  time_to.write_stats_files = now;
  time_to.write_bridge_stats = now;
  time_to.check_port_forwarding = now;
  time_to.launch_reachability_tests = now;
  time_to.retry_dns_init = now;
  time_to.next_heartbeat = now;
  time_to.check_descriptor = now;
  time_to.check_for_correct_dns = now;
  time_to.check_ed_keys = now;
}

static void
test_run_scheduled_events__writes_cell_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->CellStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  rep_hist_buffer_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  rep_hist_buffer_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_dir_req_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->DirReqStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  geoip_dirreq_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  geoip_dirreq_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_entry_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->EntryStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  geoip_entry_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  geoip_entry_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_hidden_service_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->HiddenServiceStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  rep_hist_hs_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  rep_hist_hs_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_exit_port_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->ExitPortStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  rep_hist_exit_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  rep_hist_exit_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_conn_direction_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->ConnDirectionStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  rep_hist_conn_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);

  time_to.write_stats_files = before_now;
  rep_hist_conn_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_bridge_authoritative_dir_stats_to_disk(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  mock_options->BridgeAuthoritativeDir = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  time_to.write_stats_files = before_now;
  rep_hist_desc_stats_init(0);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, before_now + 60*60);
  rep_hist_desc_stats_term();

  time_to.write_stats_files = before_now;
  rep_hist_desc_stats_init(now - WRITE_STATS_INTERVAL + 1);
  run_scheduled_events(now);
  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);
  rep_hist_desc_stats_term();

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

NS_DECL(int, pt_proxies_configuration_pending, (void));

int
NS(pt_proxies_configuration_pending)(void)
{
  CALLED(pt_proxies_configuration_pending)++;
  return 0;
};

static void
test_run_scheduled_events__fetches_dir_descriptors(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  NS_MOCK(pt_proxies_configuration_pending);
  MOCK(get_or_state, get_or_state_mock);

  time_to.try_getting_descriptors = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.try_getting_descriptors, OP_EQ, now + 10);

  done:
    UNMOCK(get_or_state);
    NS_UNMOCK(pt_proxies_configuration_pending);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__resets_descriptor_failures(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  MOCK(get_or_state, get_or_state_mock);

  time_to.reset_descriptor_failures = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.reset_descriptor_failures, OP_EQ, now + 60*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__changes_tls_context(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  MOCK(get_or_state, get_or_state_mock);

  time_to.last_rotated_x509_certificate = now - MAX_SSL_KEY_LIFETIME_INTERNAL - 1;
  run_scheduled_events(now);
  tt_int_op(time_to.last_rotated_x509_certificate, OP_EQ, now);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__adds_entropy(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  time_t before_now = now - 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  MOCK(get_or_state, get_or_state_mock);

  time_to.add_entropy = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.add_entropy, OP_EQ, now + 60*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

#define RUN_SCHEDULED_EVENTS(name, flags) \
  { #name, test_run_scheduled_events__##name, (flags), NULL, NULL }

struct testcase_t main_tests[] = {
  RUN_SCHEDULED_EVENTS(writes_cell_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_dir_req_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_entry_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_hidden_service_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_exit_port_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_conn_direction_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_bridge_authoritative_dir_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(fetches_dir_descriptors, 0),
  RUN_SCHEDULED_EVENTS(resets_descriptor_failures, 0),
  RUN_SCHEDULED_EVENTS(changes_tls_context, 0),
  RUN_SCHEDULED_EVENTS(adds_entropy, 0),
  END_OF_TESTCASES
};