/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONFIG_PRIVATE
#include "or.h"
#include "confparse.h"
#include "config.h"
#include "test.h"
#include "geoip.h"

#define ROUTERSET_PRIVATE
#include "routerset.h"

#include "log_test_helpers.h"

#define NS_MODULE test_options

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
  result->opt->LogTimeGranularity = 1;
  result->opt->TokenBucketRefillInterval = 1;

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
  tt_assert(!msg);

  free_options_test_data(tdata);
  tdata = get_options_test_data("DataDirectory /tmp/somewhere");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!msg);

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
  (void)ret;
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

static void
test_options_validate__authdir(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_INFO);
  options_test_data_t *tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                                     "Address this.should.not_exist.example.org");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Failed to resolve/guess local address. See logs for details.");
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Could not resolve local Address 'this.should.not_exist.example.org'. Failing.\n");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!msg);



  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Authoritative directory servers must set ContactInfo");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "TestingTorNetwork 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "AuthoritativeDir is set, but none of (Bridge/V3)AuthoritativeDir is set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "AuthoritativeDir is set, but none of (Bridge/V3)AuthoritativeDir is set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "RecommendedVersions 1.2, 3.14\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(tdata->opt->RecommendedClientVersions->value, OP_EQ, "1.2, 3.14");
  tt_str_op(tdata->opt->RecommendedServerVersions->value, OP_EQ, "1.2, 3.14");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "RecommendedVersions 1.2, 3.14\n"
                                "RecommendedClientVersions 25\n"
                                "RecommendedServerVersions 4.18\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(tdata->opt->RecommendedClientVersions->value, OP_EQ, "25");
  tt_str_op(tdata->opt->RecommendedServerVersions->value, OP_EQ, "4.18");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "VersioningAuthoritativeDirectory 1\n"
                                "RecommendedVersions 1.2, 3.14\n"
                                "RecommendedClientVersions 25\n"
                                "RecommendedServerVersions 4.18\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "AuthoritativeDir is set, but none of (Bridge/V3)AuthoritativeDir is set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "VersioningAuthoritativeDirectory 1\n"
                                "RecommendedServerVersions 4.18\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Versioning authoritative dir servers must set Recommended*Versions.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "VersioningAuthoritativeDirectory 1\n"
                                "RecommendedClientVersions 4.18\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Versioning authoritative dir servers must set Recommended*Versions.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "UseEntryGuards 1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Authoritative directory servers can't set UseEntryGuards. Disabling.\n");
  tt_int_op(tdata->opt->UseEntryGuards, OP_EQ, 0);

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "V3AuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Authoritative directories always try to download extra-info documents. Setting DownloadExtraInfo.\n");
  tt_int_op(tdata->opt->DownloadExtraInfo, OP_EQ, 1);

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "DownloadExtraInfo 1\n"
                                "V3AuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(0), OP_NE, "Authoritative directories always try to download extra-info documents. Setting DownloadExtraInfo.\n");
  tt_int_op(tdata->opt->DownloadExtraInfo, OP_EQ, 1);


  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "AuthoritativeDir is set, but none of (Bridge/V3)AuthoritativeDir is set.");


  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "V3BandwidthsFile non-existant-file\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no DirPort set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "V3BandwidthsFile non-existant-file\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(NULL, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no DirPort set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "GuardfractionFile non-existant-file\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no DirPort set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "GuardfractionFile non-existant-file\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  options_validate(NULL, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no DirPort set.");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__relay_with_hidden_services(void *ignored)
{
  (void)ignored;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_DEBUG);
  options_test_data_t *tdata = get_options_test_data("ORListenAddress 127.0.0.1:5555\n"
                                                     "ORPort 955\n"
                                                     "HiddenServiceDir /Library/Tor/var/lib/tor/hidden_service/\n"
                                                     "HiddenServicePort 80 127.0.0.1:8080\n");

  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "Tor is currently configured as a relay and a hidden service. "
            "That's not very secure: you should probably run your hidden service "
            "in a separate Tor process, at least -- see "
            "https://trac.torproject.org/8742\n");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

// TODO: it doesn't seem possible to hit the case of having no port lines at all, since there will be a default created for SocksPort
/* static void */
/* test_options_validate__ports(void *ignored) */
/* { */
/*   (void)ignored; */
/*   int ret; */
/*   char *msg; */
/*   int previous_log = setup_capture_of_logs(LOG_WARN); */
/*   options_test_data_t *tdata = get_options_test_data(""); */

/*   ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); */
/*   tt_str_op(mock_saved_log_at(0), OP_EQ, "SocksPort, TransPort, NATDPort, DNSPort, and ORPort are all " */
/*         "undefined, and there aren't any hidden services configured.  " */
/*         "Tor will still run, but probably won't do anything.\n"); */

/*  done: */
/*   teardown_capture_of_logs(previous_log); */
/*   free_options_test_data(tdata); */
/*   tor_free(msg); */
/* } */

static void
test_options_validate__transproxy(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata;

#ifdef USE_TRANSPARENT
  // Test default trans proxy
  tdata = get_options_test_data("TransProxyType default\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->TransProxyType_parsed, OP_EQ, TPT_DEFAULT);

  // Test pf-divert trans proxy
  free_options_test_data(tdata);
  tdata = get_options_test_data("TransProxyType pf-divert\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);

#if !defined(__OpenBSD__) && !defined( DARWIN )
  tt_str_op(msg, OP_EQ, "pf-divert is a OpenBSD-specific and OS X/Darwin-specific feature.");
#else
  tt_int_op(tdata->opt->TransProxyType_parsed, OP_EQ, TPT_PF_DIVERT);
  tt_str_op(msg, OP_EQ, "Cannot use TransProxyType without any valid TransPort or TransListenAddress.");
#endif

  // Test tproxy trans proxy
  free_options_test_data(tdata);
  tdata = get_options_test_data("TransProxyType tproxy\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);

#if !defined(__linux__)
  tt_str_op(msg, OP_EQ, "TPROXY is a Linux-specific feature.");
#else
  tt_int_op(tdata->opt->TransProxyType_parsed, OP_EQ, TPT_TPROXY);
  tt_str_op(msg, OP_EQ, "Cannot use TransProxyType without any valid TransPort or TransListenAddress.");
#endif

  // Test ipfw trans proxy
  free_options_test_data(tdata);
  tdata = get_options_test_data("TransProxyType ipfw\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);

#if !defined(__FreeBSD__) && !defined( DARWIN )
  tt_str_op(msg, OP_EQ, "ipfw is a FreeBSD-specificand OS X/Darwin-specific feature.");
#else
  tt_int_op(tdata->opt->TransProxyType_parsed, OP_EQ, TPT_IPFW);
  tt_str_op(msg, OP_EQ, "Cannot use TransProxyType without any valid TransPort or TransListenAddress.");
#endif

  // Test unknown trans proxy
  free_options_test_data(tdata);
  tdata = get_options_test_data("TransProxyType non-existant\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Unrecognized value for TransProxyType");

  // Test trans proxy success
  free_options_test_data(tdata);

#if defined(linux)
  tdata = get_options_test_data("TransProxyType tproxy\n"
                                "TransPort 127.0.0.1:123\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!msg);
#endif
#if defined(__FreeBSD__) || defined( DARWIN )
  tdata = get_options_test_data("TransProxyType ipfw\n"
                                "TransPort 127.0.0.1:123\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!msg);
#endif
#if defined(__OpenBSD__)
  tdata = get_options_test_data("TransProxyType pf-divert\n"
                                "TransPort 127.0.0.1:123\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!msg);
#endif

#else
  tdata = get_options_test_data("TransPort 127.0.0.1:555\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "TransPort and TransListenAddress are disabled in this build.");
#endif

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

NS_DECL(country_t, geoip_get_country, (const char *country));

static country_t
NS(geoip_get_country)(const char *countrycode)
{
  (void)countrycode;
  CALLED(geoip_get_country)++;

  return 1;
}

static void
test_options_validate__exclude_nodes(void *ignored)
{
  (void)ignored;

  NS_MOCK(geoip_get_country);

  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);
  options_test_data_t *tdata = get_options_test_data("ExcludeExitNodes {us}\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(smartlist_len(tdata->opt->ExcludeExitNodesUnion_->list), OP_EQ, 1);
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 0)), OP_EQ, "{us}");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {uk}\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(smartlist_len(tdata->opt->ExcludeExitNodesUnion_->list), OP_EQ, 1);
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 0)), OP_EQ, "{uk}");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {uk}\n"
                                "ExcludeExitNodes {us} {uk}\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(smartlist_len(tdata->opt->ExcludeExitNodesUnion_->list), OP_EQ, 2);
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 0)), OP_EQ, "{us} {uk}");
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 1)), OP_EQ, "{uk}");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {uk}\n"
                                "StrictNodes 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "You have asked to exclude certain relays from all positions "
            "in your circuits. Expect hidden services and other Tor "
            "features to be broken in unpredictable ways.\n");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {uk}\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_NE, "You have asked to exclude certain relays from all positions "
            "in your circuits. Expect hidden services and other Tor "
            "features to be broken in unpredictable ways.\n");

 done:
  NS_UNMOCK(geoip_get_country);
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__scheduler(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_DEBUG);
  options_test_data_t *tdata = get_options_test_data("SchedulerLowWaterMark__ 0\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Bad SchedulerLowWaterMark__ option\n");

  // TODO: this test cannot run on platforms where UINT32_MAX is == to UINT64_MAX.
  // I suspect it's unlikely this branch can actually happen
  /* free_options_test_data(tdata); */
  /* tdata = get_options_test_data("SchedulerLowWaterMark 10000000000000000000\n"); */
  /* tdata->opt->SchedulerLowWaterMark__ = (uint64_t)UINT32_MAX; */
  /* tdata->opt->SchedulerLowWaterMark__++; */
  /* mock_clean_saved_logs(); */
  /* ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); */
  /* tt_int_op(ret, OP_EQ, -1); */
  /* tt_str_op(mock_saved_log_at(1), OP_EQ, "Bad SchedulerLowWaterMark__ option\n"); */

  free_options_test_data(tdata);
  tdata = get_options_test_data("SchedulerLowWaterMark__ 42\n"
                                "SchedulerHighWaterMark__ 42\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Bad SchedulerHighWaterMark option\n");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__node_families(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("NodeFamily flux, flax\n"
                                                     "NodeFamily somewhere\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(tdata->opt->NodeFamilySets);
  tt_int_op(smartlist_len(tdata->opt->NodeFamilySets), OP_EQ, 2);
  tt_str_op((char *)(smartlist_get(((routerset_t *)smartlist_get(tdata->opt->NodeFamilySets, 0))->list, 0)), OP_EQ, "flux");
  tt_str_op((char *)(smartlist_get(((routerset_t *)smartlist_get(tdata->opt->NodeFamilySets, 0))->list, 1)), OP_EQ, "flax");
  tt_str_op((char *)(smartlist_get(((routerset_t *)smartlist_get(tdata->opt->NodeFamilySets, 1))->list, 0)), OP_EQ, "somewhere");

  free_options_test_data(tdata);
  tdata = get_options_test_data("SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(!tdata->opt->NodeFamilySets);

  free_options_test_data(tdata);
  tdata = get_options_test_data("NodeFamily !flux\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(tdata->opt->NodeFamilySets);
  tt_int_op(smartlist_len(tdata->opt->NodeFamilySets), OP_EQ, 0);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__tlsec(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_DEBUG);
  options_test_data_t *tdata = get_options_test_data("TLSECGroup ed25519\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "Unrecognized TLSECGroup: Falling back to the default.\n");
  tt_assert(!tdata->opt->TLSECGroup);

  free_options_test_data(tdata);
  tdata = get_options_test_data("TLSECGroup P224\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_NE, "Unrecognized TLSECGroup: Falling back to the default.\n");
  tt_assert(tdata->opt->TLSECGroup);

  free_options_test_data(tdata);
  tdata = get_options_test_data("TLSECGroup P256\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(0), OP_NE, "Unrecognized TLSECGroup: Falling back to the default.\n");
  tt_assert(tdata->opt->TLSECGroup);

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__token_bucket(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("");

  tdata->opt->TokenBucketRefillInterval = 0;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "TokenBucketRefillInterval must be between 1 and 1000 inclusive.");

  tdata->opt->TokenBucketRefillInterval = 1001;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "TokenBucketRefillInterval must be between 1 and 1000 inclusive.");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__recommended_packages(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);
  options_test_data_t *tdata = get_options_test_data("RecommendedPackages foo 1.2 http://foo.com sha1=123123123123\n"
                                                     "RecommendedPackages invalid-package-line\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_NE, "Invalid RecommendedPackage line invalid-package-line will be ignored\n");

 done:
  teardown_capture_of_logs(previous_log);
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
  { "validate__authdir", test_options_validate__authdir, TT_FORK, NULL, NULL },
  { "validate__relay_with_hidden_services", test_options_validate__relay_with_hidden_services, TT_FORK, NULL, NULL },
  { "validate__transproxy", test_options_validate__transproxy, TT_FORK, NULL, NULL },
  { "validate__exclude_nodes", test_options_validate__exclude_nodes, TT_FORK, NULL, NULL },
  { "validate__scheduler", test_options_validate__scheduler, TT_FORK, NULL, NULL },
  { "validate__node_families", test_options_validate__node_families, TT_FORK, NULL, NULL },
  { "validate__tlsec", test_options_validate__tlsec, TT_FORK, NULL, NULL },
  { "validate__token_bucket", test_options_validate__token_bucket, TT_FORK, NULL, NULL },
  { "validate__recommended_packages", test_options_validate__recommended_packages, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
