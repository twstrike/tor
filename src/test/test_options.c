/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONFIG_PRIVATE
#include "or.h"
#include "confparse.h"
#include "config.h"
#include "test.h"

#include "log_test_helpers.h"

typedef struct {
  int severity;
  uint32_t domain;
  char *msg;
} logmsg_t;

static smartlist_t *messages = NULL;

static void
log_cback(int severity, uint32_t domain, const char *msg)
{
  logmsg_t *x = tor_malloc(sizeof(*x));
  x->severity = severity;
  x->domain = domain;
  x->msg = tor_strdup(msg);
  if (!messages)
    messages = smartlist_new();
  smartlist_add(messages, x);
}

static void
setup_log_callback(void)
{
  log_severity_list_t lst;
  memset(&lst, 0, sizeof(lst));
  lst.masks[LOG_ERR - LOG_ERR] = ~0;
  lst.masks[LOG_WARN - LOG_ERR] = ~0;
  lst.masks[LOG_NOTICE - LOG_ERR] = ~0;
  add_callback_log(&lst, log_cback);
}

static char *
dump_logs(void)
{
  smartlist_t *msgs;
  char *out;
  if (! messages)
    return tor_strdup("");
  msgs = smartlist_new();
  SMARTLIST_FOREACH_BEGIN(messages, logmsg_t *, x) {
    smartlist_add_asprintf(msgs, "[%s] %s",
                           log_level_to_string(x->severity), x->msg);
  } SMARTLIST_FOREACH_END(x);
  out = smartlist_join_strings(msgs, "", 0, NULL);
  SMARTLIST_FOREACH(msgs, char *, cp, tor_free(cp));
  smartlist_free(msgs);
  return out;
}

static void
clear_log_messages(void)
{
  if (!messages)
    return;
  SMARTLIST_FOREACH(messages, logmsg_t *, m,
                    { tor_free(m->msg); tor_free(m); });
  smartlist_free(messages);
  messages = NULL;
}

static void
test_options_validate_impl(const char *configuration,
                           const char *expect_errmsg,
                           int expect_log_severity,
                           const char *expect_log)
{
  or_options_t *opt = options_new();
  or_options_t *dflt;
  config_line_t *cl=NULL;
  char *msg=NULL;
  int r;
  opt->command = CMD_RUN_TOR;
  options_init(opt);

  dflt = config_dup(&options_format, opt);
  clear_log_messages();

  r = config_get_lines(configuration, &cl, 1);
  tt_int_op(r, OP_EQ, 0);

  r = config_assign(&options_format, opt, cl, 0, 0, &msg);
  tt_int_op(r, OP_EQ, 0);

  r = options_validate(NULL, opt, dflt, 0, &msg);
  if (expect_errmsg && !msg) {
    TT_DIE(("Expected error message <%s> from <%s>, but got none.",
            expect_errmsg, configuration));
  } else if (expect_errmsg && !strstr(msg, expect_errmsg)) {
    TT_DIE(("Expected error message <%s> from <%s>, but got <%s>.",
            expect_errmsg, configuration, msg));
  } else if (!expect_errmsg && msg) {
    TT_DIE(("Expected no error message from <%s> but got <%s>.",
            configuration, msg));
  }
  tt_int_op((r == 0), OP_EQ, (msg == NULL));

  if (expect_log) {
    int found = 0;
    if (messages) {
      SMARTLIST_FOREACH_BEGIN(messages, logmsg_t *, m) {
        if (m->severity == expect_log_severity &&
            strstr(m->msg, expect_log)) {
          found = 1;
          break;
        }
      } SMARTLIST_FOREACH_END(m);
    }
    if (!found) {
      tor_free(msg);
      msg = dump_logs();
      TT_DIE(("Expected log message [%s] %s from <%s>, but got <%s>.",
              log_level_to_string(expect_log_severity), expect_log,
              configuration, msg));
    }
  }

 done:
  config_free_lines(cl);
  or_options_free(opt);
  or_options_free(dflt);
  tor_free(msg);
  clear_log_messages();
}

#define WANT_ERR(config, msg)                           \
  test_options_validate_impl((config), (msg), 0, NULL)
#define WANT_LOG(config, severity, msg)                         \
  test_options_validate_impl((config), NULL, (severity), (msg))
#define WANT_ERR_LOG(config, msg, severity, logmsg)                     \
  test_options_validate_impl((config), (msg), (severity), (logmsg))
#define OK(config)                                      \
  test_options_validate_impl((config), NULL, 0, NULL)

static void
test_options_validate(void *arg)
{
  (void)arg;
  setup_log_callback();

  WANT_ERR("ExtORPort 500000", "Invalid ExtORPort");

  WANT_ERR_LOG("ServerTransportOptions trebuchet",
               "ServerTransportOptions did not parse",
               LOG_WARN, "Too few arguments");
  OK("ServerTransportOptions trebuchet sling=snappy");
  OK("ServerTransportOptions trebuchet sling=");
  WANT_ERR_LOG("ServerTransportOptions trebuchet slingsnappy",
               "ServerTransportOptions did not parse",
               LOG_WARN, "\"slingsnappy\" is not a k=v");

  clear_log_messages();
  return;
}

static char *fixed_get_uname_result = NULL;

static const char *
fixed_get_uname(void)
{
  return fixed_get_uname_result;
}

typedef struct {
  or_options_t *old_opt;
  or_options_t *opt;
  or_options_t *def_opt;
} options_test_data_t;

static options_test_data_t *
get_options_test_data(char *conf)
{
  config_line_t *cl=NULL;
  options_test_data_t *result = tor_malloc(sizeof(options_test_data_t));
  result->opt = options_new();
  result->old_opt = options_new();
  result->def_opt = options_new();
  config_get_lines(conf, &cl, 1);
  config_assign(&options_format, result->opt, cl, 0, 0, NULL);

  return result;
}

static void
free_options_test_data(options_test_data_t *td)
{
  or_options_free(td->old_opt);
  or_options_free(td->opt);
  or_options_free(td->def_opt);
  tor_free(td);
}


static void
test_options_validate__uname_for_server(void *ignored)
{
  (void)ignored;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("ORListenAddress 127.0.0.1:5555");
  int previous_log = setup_capture_of_logs(LOG_WARN);

  MOCK(get_uname, fixed_get_uname);
  fixed_get_uname_result = "Windows 95";
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Tor is running as a server, but you are running Windows 95; this probably won't work. See https://www.torproject.org/docs/faq.html#BestOSForRelay for details.\n");

  fixed_get_uname_result = "Windows 98";
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Tor is running as a server, but you are running Windows 98; this probably won't work. See https://www.torproject.org/docs/faq.html#BestOSForRelay for details.\n");

  fixed_get_uname_result = "Windows Me";
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Tor is running as a server, but you are running Windows Me; this probably won't work. See https://www.torproject.org/docs/faq.html#BestOSForRelay for details.\n");

  fixed_get_uname_result = "Windows 2000";
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);

 done:
  UNMOCK(get_uname);
  free_options_test_data(tdata);
  tor_free(msg);
  teardown_capture_of_logs(previous_log);
}

static void
test_options_validate__outbound_addresses(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("OutboundBindAddress xxyy!!!sdfaf");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__data_directory(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("DataDirectory longreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONGlongreallylongLONGLONG"); // 440 characters long

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Invalid DataDirectory");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__nickname(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("Nickname ThisNickNameIsABitTooLong");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Nickname 'ThisNickNameIsABitTooLong' is wrong length or contains illegal characters.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("Nickname AMoreValidNick");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Failed to validate Log options. See logs for details.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("DataDirectory /tmp/somewhere");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Failed to validate Log options. See logs for details.");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__contactinfo(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("ORListenAddress 127.0.0.1:5555\nORPort 955");
  int previous_log = setup_capture_of_logs(LOG_DEBUG);
  tdata->opt->ContactInfo = NULL;

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Your ContactInfo config option is not set. Please consider setting it, so we can contact you if your server is misconfigured or something else goes wrong.\n");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ORListenAddress 127.0.0.1:5555\nORPort 955\nContactInfo hella@example.org");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_NE, "Your ContactInfo config option is not set. Please consider setting it, so we can contact you if your server is misconfigured or something else goes wrong.\n");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

extern int quiet_level;

static void
test_options_validate__logs(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int orig_quiet_level = quiet_level;
  options_test_data_t *tdata = get_options_test_data("");
  tdata->opt->Logs = NULL;
  tdata->opt->RunAsDaemon = 0;

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(tdata->opt->Logs->key, OP_EQ, "Log");
  tt_str_op(tdata->opt->Logs->value, OP_EQ, "notice stdout");

  tdata->opt->Logs = NULL;
  quiet_level = 1;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(tdata->opt->Logs->key, OP_EQ, "Log");
  tt_str_op(tdata->opt->Logs->value, OP_EQ, "warn stdout");

  tdata->opt->Logs = NULL;
  quiet_level = 2;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_assert(!tdata->opt->Logs);

  tdata->opt->Logs = NULL;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 1, &msg);
  tt_assert(!tdata->opt->Logs);

  tdata->opt->RunAsDaemon = 1;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_assert(!tdata->opt->Logs);

  config_line_t *cl=NULL;
  config_get_lines("Log foo", &cl, 1);
  tdata->opt->Logs = cl;
  tdata->opt->RunAsDaemon = 0;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op((intptr_t)tdata->opt->Logs, OP_EQ, (intptr_t)cl);

 done:
  quiet_level = orig_quiet_level;
  free_options_test_data(tdata);
  tor_free(msg);
}



struct testcase_t options_tests[] = {
  { "validate", test_options_validate, TT_FORK, NULL, NULL },
  { "validate__uname_for_server", test_options_validate__uname_for_server, TT_FORK, NULL, NULL },
  { "validate__outbound_addresses", test_options_validate__outbound_addresses, TT_FORK, NULL, NULL },
  { "validate__data_directory", test_options_validate__data_directory, TT_FORK, NULL, NULL },
  { "validate__nickname", test_options_validate__nickname, TT_FORK, NULL, NULL },
  { "validate__contactinfo", test_options_validate__contactinfo, TT_FORK, NULL, NULL },
  { "validate__logs", test_options_validate__logs, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
