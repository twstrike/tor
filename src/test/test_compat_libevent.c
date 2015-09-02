/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define COMPAT_LIBEVENT_PRIVATE
#include "orconfig.h"
#include "or.h"

#include "test.h"

#include "compat_libevent.h"

#ifdef HAVE_EVENT2_EVENT_H
#include <event2/event.h>
#include <event2/thread.h>
#ifdef USE_BUFFEREVENTS
#include <event2/bufferevent.h>
#endif
#else
#include <event.h>
#endif

#include "log_test_helpers.h"

#define NS_MODULE compat_libevent

static void
test_compat_libevent_logging_callback(void *ignored)
{
  (void)ignored;
  int previous_log = setup_capture_of_logs(LOG_DEBUG);

  libevent_logging_callback(_EVENT_LOG_DEBUG, "hello world");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message from libevent: hello world\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_DEBUG);

  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_MSG, "hello world another time");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message from libevent: hello world another time\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_WARN, "hello world a third time");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Warning from libevent: hello world a third time\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_WARN);

  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_ERR, "hello world a fourth time");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Error from libevent: hello world a fourth time\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_ERR);

  mock_clean_saved_logs();
  libevent_logging_callback(42, "hello world a fifth time");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message [42] from libevent: hello world a fifth time\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_WARN);

  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_DEBUG, "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
                            "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message from libevent: 012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_DEBUG);

  mock_clean_saved_logs();
  libevent_logging_callback(42, "xxx\n");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message [42] from libevent: xxx\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_WARN);

  suppress_libevent_log_msg("something");
  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_MSG, "hello there");
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Message from libevent: hello there\n");
  tt_int_op(mock_saved_severity_at(0), OP_EQ, LOG_INFO);

  mock_clean_saved_logs();
  libevent_logging_callback(_EVENT_LOG_MSG, "hello there something else");
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

  // No way of verifying the result of this, it seems =/
  configure_libevent_logging();

 done:
  suppress_libevent_log_msg(NULL);
  teardown_capture_of_logs(previous_log);
}


struct testcase_t compat_libevent_tests[] = {
  { "logging_callback", test_compat_libevent_logging_callback, 0, NULL, NULL },
  END_OF_TESTCASES
};
