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
#include "router.h"
#include "entrynodes.h"
#include "hibernate.h"
#include "dirserv.h"

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
    tor_free(mock_options);
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
    tor_free(mock_options);
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
    tor_free(mock_options);
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
    tor_free(mock_options);
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
    tor_free(mock_options);
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
    tor_free(mock_options);
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
    tor_free(mock_options);
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


NS_DECL(void, fetch_bridge_descriptors, (const or_options_t *options, time_t now));

void
NS(fetch_bridge_descriptors)(const or_options_t *options, time_t now)
{
  (void) options;
  (void) now;

  CALLED(fetch_bridge_descriptors)++;
}

static void
test_run_scheduled_events__fetches_bridge_descriptors(void *data)
{
  time_t now = time(NULL);
  time_t after_now = now + 60;
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();
  init_mock_options();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);
  NS_MOCK(fetch_bridge_descriptors);

  mock_options->UseBridges = 1;
  mock_options->DisableNetwork = 0;
  run_scheduled_events(now);

  tt_int_op(1, OP_EQ, CALLED(fetch_bridge_descriptors));

  done:
    NS_UNMOCK(fetch_bridge_descriptors);
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options);
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
  crypto_pk_t *identity_pkey = pk_generate(0);
  (void) data;

  rend_cache_init();
  init_connection_lists();

  init_mock_state();

  set_all_times_to(after_now);
  mock_state->next_write = after_now;

  MOCK(get_or_state, get_or_state_mock);

  set_client_identity_key(identity_pkey);

  time_to.last_rotated_x509_certificate = now - MAX_SSL_KEY_LIFETIME_INTERNAL - 1;
  run_scheduled_events(now);
  tt_int_op(time_to.last_rotated_x509_certificate, OP_EQ, now);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
    set_client_identity_key(NULL);
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

static void
test_run_scheduled_events__checks_auth_certificate_expiriry(void *data)
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

  time_to.check_v3_certificate = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_v3_certificate, OP_EQ, now + 5*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__checks_network_status_expiry(void *data)
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

  time_to.check_for_expired_networkstatus = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_for_expired_networkstatus, OP_EQ, now + 2*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__cleans_caches(void *data)
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

  time_to.clean_caches = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.clean_caches, OP_EQ, now + 30*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__retries_dns_init(void *data)
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

  time_to.retry_dns_init = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.retry_dns_init, OP_EQ, now + 10*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

NS_DECL(int, server_mode, (const or_options_t *options));
NS_DECL(int, have_completed_a_circuit, (void));
NS_DECL(int, we_are_hibernating, (void));
NS_DECL(long, get_uptime, (void));
NS_DECL(time_t, get_onion_key_set_at, (void));

static int
NS(server_mode)(const or_options_t *options)
{
  (void)options;

  return 1;
}

static int
NS(have_completed_a_circuit)(void)
{
  return 1;
}

static int
NS(we_are_hibernating)(void)
{
  return 0;
}

static long
NS(get_uptime)(void)
{
  return TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT + 1;
}

static time_t
NS(get_onion_key_set_at)(void)
{
  return time(NULL) + MIN_ONION_KEY_LIFETIME;
}

static void
test_run_scheduled_events__checks_descriptor(void *data)
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

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  mock_options->DisableNetwork = 1;
  time_to.check_descriptor = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_descriptor, OP_EQ, before_now);

  mock_options->DisableNetwork = 0;
  time_to.check_descriptor = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_descriptor, OP_EQ, now + 60);

  NS_MOCK(server_mode);
  NS_MOCK(get_onion_key_set_at);
  NS_MOCK(have_completed_a_circuit);
  NS_MOCK(we_are_hibernating);

  time_to.check_descriptor = before_now;
  time_to.recheck_bandwidth = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_descriptor, OP_EQ, now + 60);
  tt_int_op(time_to.recheck_bandwidth, OP_EQ, before_now);

  NS_MOCK(get_uptime);

  time_to.check_descriptor = before_now;
  time_to.recheck_bandwidth = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_descriptor, OP_EQ, now + 60);
  tt_int_op(time_to.recheck_bandwidth, OP_EQ, now + 12*60*60);

  done:
    NS_UNMOCK(get_uptime);
    NS_UNMOCK(we_are_hibernating);
    NS_UNMOCK(have_completed_a_circuit);
    NS_UNMOCK(get_onion_key_set_at);
    NS_UNMOCK(server_mode);
    UNMOCK(get_or_state);
    UNMOCK(get_options);
    tor_free(mock_options->DataDirectory);
    tor_free(mock_options);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__launches_reachability_test(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);

  mock_options->BridgeAuthoritativeDir = 1;

  time_to.launch_reachability_tests = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.launch_reachability_tests, OP_EQ, now + REACHABILITY_TEST_INTERVAL);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__downrates_stability(void *data)
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

  MOCK(get_or_state, get_or_state_mock);

  time_to.downrate_stability = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.downrate_stability, OP_EQ, now + 12*60*60);

  done:
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__saves_stability(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);

  mock_options->BridgeAuthoritativeDir = 1;

  tor_free(mock_options->DataDirectory);
  mock_options->DataDirectory = tor_strdup(get_fname("main_datadir_test"));

  time_to.downrate_stability = before_now;
  time_to.save_stability = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.save_stability, OP_EQ, now + 30*60);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options->DataDirectory);
    tor_free(mock_options);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_bridge_stats_to_disk(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);

  mock_options->BridgeRelay = 1;
  mock_options->BridgeRecordUsageByCountry = 1;

  time_to.write_bridge_stats = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.write_bridge_stats, OP_EQ, now + WRITE_STATS_INTERVAL);

  geoip_bridge_stats_init(before_now);

  time_to.write_bridge_stats = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.write_bridge_stats, OP_EQ, before_now + WRITE_STATS_INTERVAL);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_bridge_status_file(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);

  mock_options->BridgeAuthoritativeDir = 1;

  tor_free(mock_options->DataDirectory);
  mock_options->DataDirectory = tor_strdup(get_fname("main_datadir_test"));

  time_to.write_bridge_status_file = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.write_bridge_status_file, OP_EQ, now + 30*60);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options->DataDirectory);
    tor_free(mock_options);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__writes_heartbeat_messages(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);

  mock_options->HeartbeatPeriod = 59;

  time_to.next_heartbeat = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.next_heartbeat, OP_EQ, now + mock_options->HeartbeatPeriod);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

NS_DECL(int,
public_server_mode, (const or_options_t *options));

static int
NS(public_server_mode)(const or_options_t *options)
{
  (void)options;
  return 1;
}

NS_DECL(const routerinfo_t *, router_get_my_routerinfo, (void));

static routerinfo_t *mock_routerinfo;
static const routerinfo_t *
NS(router_get_my_routerinfo)(void)
{
  tor_assert(mock_routerinfo);
  return mock_routerinfo;
}

static void
test_run_scheduled_events__checks_for_correct_dns(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);
  NS_MOCK(public_server_mode);
  NS_MOCK(router_get_my_routerinfo);

  mock_routerinfo = tor_malloc(sizeof(routerinfo_t));
  mock_routerinfo->policy_is_reject_star = 0;

  time_to.check_for_correct_dns = 0;
  run_scheduled_events(now);
  tt_int_op(time_to.check_for_correct_dns, OP_GE, now + 60);
  tt_int_op(time_to.check_for_correct_dns, OP_LE, now + 180);

  mock_options->ServerDNSDetectHijacking = 0;

  time_to.check_for_correct_dns = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_for_correct_dns, OP_GE, now + 12*3600);
  tt_int_op(time_to.check_for_correct_dns, OP_LE, now + 2*12*3600);

  done:
    NS_UNMOCK(router_get_my_routerinfo);
    NS_UNMOCK(public_server_mode);
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

static void
test_run_scheduled_events__checks_port_forwarding(void *data)
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

  MOCK(get_or_state, get_or_state_mock);
  MOCK(get_options, get_options_mock);
  NS_MOCK(server_mode);

  mock_options->PortForwarding = 1;
  tor_free(mock_options->DataDirectory);
  mock_options->DataDirectory = tor_strdup(get_fname("main_datadir_test"));

  time_to.check_port_forwarding = before_now;
  run_scheduled_events(now);
  tt_int_op(time_to.check_port_forwarding, OP_EQ, now + 5);

  done:
    NS_UNMOCK(server_mode);
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    tor_free(mock_options->DataDirectory);
    tor_free(mock_options);
    rend_cache_free_all();
}

#define RUN_SCHEDULED_EVENTS(name, flags) \
  { #name, test_run_scheduled_events__##name, TT_FORK, NULL, NULL }

struct testcase_t main_tests[] = {
  RUN_SCHEDULED_EVENTS(writes_cell_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_dir_req_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_entry_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_hidden_service_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_exit_port_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_conn_direction_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_bridge_authoritative_dir_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(writes_bridge_stats_to_disk, 0),
  RUN_SCHEDULED_EVENTS(fetches_dir_descriptors, 0),
  RUN_SCHEDULED_EVENTS(fetches_bridge_descriptors, 0),
  RUN_SCHEDULED_EVENTS(resets_descriptor_failures, 0),
  RUN_SCHEDULED_EVENTS(changes_tls_context, 0),
  RUN_SCHEDULED_EVENTS(adds_entropy, 0),
  RUN_SCHEDULED_EVENTS(checks_auth_certificate_expiriry, 0),
  RUN_SCHEDULED_EVENTS(checks_network_status_expiry, 0),
  RUN_SCHEDULED_EVENTS(cleans_caches, 0),
  RUN_SCHEDULED_EVENTS(retries_dns_init, 0),
  RUN_SCHEDULED_EVENTS(checks_descriptor, 0),
  RUN_SCHEDULED_EVENTS(launches_reachability_test, 0),
  RUN_SCHEDULED_EVENTS(downrates_stability, 0),
  RUN_SCHEDULED_EVENTS(saves_stability, 0),
  RUN_SCHEDULED_EVENTS(writes_bridge_status_file, 0),
  RUN_SCHEDULED_EVENTS(writes_heartbeat_messages, 0),
  RUN_SCHEDULED_EVENTS(checks_for_correct_dns, 0),
  RUN_SCHEDULED_EVENTS(checks_port_forwarding, 0),
  END_OF_TESTCASES
};
