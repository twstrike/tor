/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "test.h"

#define MAIN_PRIVATE
#include "main.h"

#define NS_MODULE main_tests

static void
test_run_scheduled_events__do_nothing(void *data)
{
  (void) data;

  done: ;
}

#define RUN_SCHEDULED_EVENTS(name, flags) \
  { #name, test_run_scheduled_events__##name, (flags), NULL, NULL }

struct testcase_t main_tests[] = {
  RUN_SCHEDULED_EVENTS(do_nothing, 0),
  END_OF_TESTCASES
};