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

  rep_hist_buffer_stats_init(now - WRITE_STATS_INTERVAL + 1);
  time_to.write_stats_files = before_now;
  mock_options->CellStatistics = 1;

  MOCK(get_options, get_options_mock);
  MOCK(get_or_state, get_or_state_mock);

  run_scheduled_events(now);

  tt_int_op(time_to.write_stats_files, OP_EQ, now + 1);

  done:
    UNMOCK(get_options);
    UNMOCK(get_or_state);
    rend_cache_free_all();
}

#define RUN_SCHEDULED_EVENTS(name, flags) \
  { #name, test_run_scheduled_events__##name, (flags), NULL, NULL }

struct testcase_t main_tests[] = {
  RUN_SCHEDULED_EVENTS(writes_cell_stats_to_disk, 0),
  END_OF_TESTCASES
};