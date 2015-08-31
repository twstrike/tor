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

#define TEST_OPTIONS_OLD_VALUES   "TestingV3AuthInitialVotingInterval 1800\n" \
  "TestingV3AuthInitialVoteDelay 300\n" \
  "TestingV3AuthInitialDistDelay 300\n" \
  "TestingClientMaxIntervalWithoutRequest 600\n" \
  "TestingDirConnectionMaxStall 600\n" \
  "TestingConsensusMaxDownloadTries 8\n" \
  "TestingDescriptorMaxDownloadTries 8\n" \
  "TestingMicrodescMaxDownloadTries 8\n" \
  "TestingCertMaxDownloadTries 8\n"


#define TEST_OPTIONS_DEFAULT_VALUES TEST_OPTIONS_OLD_VALUES "MaxClientCircuitsPending 1\n" \
  "RendPostPeriod 1000\n"                                               \
  "KeepAlivePeriod 1\n"                                                 \
  "ConnLimit 1\n"                                                       \
  "V3AuthVotingInterval 300\n"                                          \
  "V3AuthVoteDelay 20\n"                                                \
  "V3AuthDistDelay 20\n"                                                \
  "V3AuthNIntervalsValid 3\n"                                           \
  "VirtualAddrNetworkIPv4 127.192.0.0/10\n"                             \
  "VirtualAddrNetworkIPv6 [FE80::]/10\n"                                \
  "SchedulerHighWaterMark__ 42\n"                                       \
  "SchedulerLowWaterMark__ 10\n"

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
  config_get_lines(TEST_OPTIONS_OLD_VALUES, &cl, 1);
  config_assign(&options_format, result->def_opt, cl, 0, 0, NULL);
  return result;
}

static void
free_options_test_data(options_test_data_t *td)
{
  if(!td) return;
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

/* static config_line_t * */
/* mock_config_line(const char *key, const char *val) */
/* { */
/*   config_line_t *config_line = tor_malloc(sizeof(config_line_t)); */
/*   memset(config_line, 0, sizeof(config_line_t)); */
/*   config_line->key = tor_strdup(key); */
/*   config_line->value = tor_strdup(val); */
/*   return config_line; */
/* } */

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

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no DirPort set.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AuthoritativeDirectory 1\n"
                                "Address 100.200.10.1\n"
                                "DirPort 999\n"
                                "BridgeAuthoritativeDir 1\n"
                                "ContactInfo hello@hello.com\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Running as authoritative directory, but no ORPort set.");


  // TODO: This case can't be reached, since clientonly is used to check when parsing port lines as well.
  /* free_options_test_data(tdata); */
  /* tdata = get_options_test_data("AuthoritativeDirectory 1\n" */
  /*                               "Address 100.200.10.1\n" */
  /*                               "DirPort 999\n" */
  /*                               "ORPort 888\n" */
  /*                               "ClientOnly 1\n" */
  /*                               "BridgeAuthoritativeDir 1\n" */
  /*                               "ContactInfo hello@hello.com\n" */
  /*                               "SchedulerHighWaterMark__ 42\n" */
  /*                               "SchedulerLowWaterMark__ 10\n"); */
  /* mock_clean_saved_logs(); */
  /* ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); */
  /* tt_int_op(ret, OP_EQ, -1); */
  /* tt_str_op(msg, OP_EQ, "Running as authoritative directory, but ClientOnly also set."); */


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
  tdata = get_options_test_data("ExcludeNodes {cn}\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(smartlist_len(tdata->opt->ExcludeExitNodesUnion_->list), OP_EQ, 1);
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 0)), OP_EQ, "{cn}");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {cn}\n"
                                "ExcludeExitNodes {us} {cn}\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(smartlist_len(tdata->opt->ExcludeExitNodesUnion_->list), OP_EQ, 2);
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 0)), OP_EQ, "{us} {cn}");
  tt_str_op((char *)(smartlist_get(tdata->opt->ExcludeExitNodesUnion_->list, 1)), OP_EQ, "{cn}");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ExcludeNodes {cn}\n"
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
  tdata = get_options_test_data("ExcludeNodes {cn}\n"
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


static void
test_options_validate__fetch_dir(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("FetchDirInfoExtraEarly 1\n"
                                                     "FetchDirInfoEarly 0\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "FetchDirInfoExtraEarly requires that you also set FetchDirInfoEarly");

  free_options_test_data(tdata);
  tdata = get_options_test_data("FetchDirInfoExtraEarly 1\n"
                                "FetchDirInfoEarly 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_NE, "FetchDirInfoExtraEarly requires that you also set FetchDirInfoEarly");


 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__conn_limit(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("ConnLimit 0\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "ConnLimit must be greater than 0, but was set to 0");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "MaxClientCircuitsPending must be between 1 and 1024, but was set to 0");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__paths_needed(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);
  options_test_data_t *tdata = get_options_test_data("PathsNeededToBuildCircuits 0.1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(tdata->opt->PathsNeededToBuildCircuits > 0.24 && tdata->opt->PathsNeededToBuildCircuits < 0.26);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "PathsNeededToBuildCircuits is too low. Increasing to 0.25\n");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data("PathsNeededToBuildCircuits 0.99\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(tdata->opt->PathsNeededToBuildCircuits > 0.94 && tdata->opt->PathsNeededToBuildCircuits < 0.96);
  tt_int_op(mock_saved_log_number(), OP_EQ, 1);
  tt_str_op(mock_saved_log_at(0), OP_EQ, "PathsNeededToBuildCircuits is too high. Decreasing to 0.95\n");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data("PathsNeededToBuildCircuits 0.91\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_assert(tdata->opt->PathsNeededToBuildCircuits > 0.90 && tdata->opt->PathsNeededToBuildCircuits < 0.92);
  tt_int_op(mock_saved_log_number(), OP_EQ, 0);

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__max_client_circuits(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("MaxClientCircuitsPending 0\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "MaxClientCircuitsPending must be between 1 and 1024, but was set to 0");

  free_options_test_data(tdata);
  tdata = get_options_test_data("MaxClientCircuitsPending 1025\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "MaxClientCircuitsPending must be between 1 and 1024, but was set to 1025");

  free_options_test_data(tdata);
  tdata = get_options_test_data("MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "KeepalivePeriod option must be positive.");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__ports(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("FirewallPorts 65537\n"
                                                     "MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Port '65537' out of range in FirewallPorts");

  free_options_test_data(tdata);
  tdata = get_options_test_data("FirewallPorts 1\n"
                                "LongLivedPorts 124444\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Port '124444' out of range in LongLivedPorts");

  free_options_test_data(tdata);
  tdata = get_options_test_data("FirewallPorts 1\n"
                                "LongLivedPorts 2\n"
                                "RejectPlaintextPorts 112233\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Port '112233' out of range in RejectPlaintextPorts");

  free_options_test_data(tdata);
  tdata = get_options_test_data("FirewallPorts 1\n"
                                "LongLivedPorts 2\n"
                                "RejectPlaintextPorts 3\n"
                                "WarnPlaintextPorts 65536\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Port '65536' out of range in WarnPlaintextPorts");

  free_options_test_data(tdata);
  tdata = get_options_test_data("FirewallPorts 1\n"
                                "LongLivedPorts 2\n"
                                "RejectPlaintextPorts 3\n"
                                "WarnPlaintextPorts 4\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "KeepalivePeriod option must be positive.");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__reachable_addresses(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_NOTICE);
  options_test_data_t *tdata = get_options_test_data("FascistFirewall 1\n"
                                                     "MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(mock_saved_log_number(), OP_EQ, 6);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "Converting FascistFirewall config option to new format: \"ReachableDirAddresses *:80\"\n");
  tt_str_op(tdata->opt->ReachableDirAddresses->value, OP_EQ, "*:80");
  tt_str_op(mock_saved_log_at(2), OP_EQ, "Converting FascistFirewall config option to new format: \"ReachableORAddresses *:443\"\n");
  tt_str_op(tdata->opt->ReachableORAddresses->value, OP_EQ, "*:443");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data("FascistFirewall 1\n"
                                "ReachableDirAddresses *:81\n"
                                "ReachableORAddresses *:444\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");
  tdata->opt->FirewallPorts = smartlist_new();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(mock_saved_log_number(), OP_EQ, 4);
  tt_str_op(tdata->opt->ReachableDirAddresses->value, OP_EQ, "*:81");
  tt_str_op(tdata->opt->ReachableORAddresses->value, OP_EQ, "*:444");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data("FascistFirewall 1\n"
                                "FirewallPort 123\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(mock_saved_log_number(), OP_EQ, 5);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "Converting FascistFirewall and FirewallPorts config options to new format: \"ReachableAddresses *:123\"\n");
  tt_str_op(tdata->opt->ReachableAddresses->value, OP_EQ, "*:123");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data("FascistFirewall 1\n"
                                "ReachableAddresses *:82\n"
                                "ReachableAddresses *:83\n"
                                "ReachableAddresses reject *:*\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(mock_saved_log_number(), OP_EQ, 4);
  tt_str_op(tdata->opt->ReachableAddresses->value, OP_EQ, "*:82");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ReachableAddresses *:82\n"
                                "ORListenAddress 127.0.0.1:5555\n"
                                "ORPort 955\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Servers must be able to freely connect to the rest of the Internet, so they must not set Reachable*Addresses or FascistFirewall.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ReachableORAddresses *:82\n"
                                "ORListenAddress 127.0.0.1:5555\n"
                                "ORPort 955\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Servers must be able to freely connect to the rest of the Internet, so they must not set Reachable*Addresses or FascistFirewall.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("ReachableDirAddresses *:82\n"
                                "ORListenAddress 127.0.0.1:5555\n"
                                "ORPort 955\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Servers must be able to freely connect to the rest of the Internet, so they must not set Reachable*Addresses or FascistFirewall.");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__use_bridges(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("UseBridges 1\n"
                                                     "ORListenAddress 127.0.0.1:5555\n"
                                                     "ORPort 955\n"
                                                     "MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Servers must be able to freely connect to the rest of the Internet, so they must not set UseBridges.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("UseBridges 1\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_NE, "Servers must be able to freely connect to the rest of the Internet, so they must not set UseBridges.");


  NS_MOCK(geoip_get_country);
  free_options_test_data(tdata);
  tdata = get_options_test_data("UseBridges 1\n"
                                "EntryNodes {cn}\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "You cannot set both UseBridges and EntryNodes.");

 done:
  NS_UNMOCK(geoip_get_country);
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__entry_nodes(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  NS_MOCK(geoip_get_country);
  options_test_data_t *tdata = get_options_test_data("EntryNodes {cn}\n"
                                                     "UseEntryGuards 0\n"
                                                     "MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "If EntryNodes is set, UseEntryGuards must be enabled.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("EntryNodes {cn}\n"
                                "UseEntryGuards 1\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "KeepalivePeriod option must be positive.");

 done:
  NS_UNMOCK(geoip_get_country);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__invalid_nodes(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("AllowInvalidNodes something_stupid\n"
                                                     "MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Unrecognized value 'something_stupid' in AllowInvalidNodes");

  free_options_test_data(tdata);
  tdata = get_options_test_data("AllowInvalidNodes entry, middle, exit\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->AllowInvalid_, OP_EQ, ALLOW_INVALID_ENTRY | ALLOW_INVALID_EXIT | ALLOW_INVALID_MIDDLE);

  free_options_test_data(tdata);
  tdata = get_options_test_data("AllowInvalidNodes introduction, rendezvous\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->AllowInvalid_, OP_EQ, ALLOW_INVALID_INTRODUCTION | ALLOW_INVALID_RENDEZVOUS);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__safe_logging(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = get_options_test_data("MaxClientCircuitsPending 1\n"
                                                     "ConnLimit 1\n"
                                                     "SchedulerHighWaterMark__ 42\n"
                                                     "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->SafeLogging_, OP_EQ, SAFELOG_SCRUB_NONE);

  free_options_test_data(tdata);
  tdata = get_options_test_data("SafeLogging 0\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->SafeLogging_, OP_EQ, SAFELOG_SCRUB_NONE);


  free_options_test_data(tdata);
  tdata = get_options_test_data("SafeLogging Relay\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->SafeLogging_, OP_EQ, SAFELOG_SCRUB_RELAY);

  free_options_test_data(tdata);
  tdata = get_options_test_data("SafeLogging 1\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_int_op(tdata->opt->SafeLogging_, OP_EQ, SAFELOG_SCRUB_ALL);

  free_options_test_data(tdata);
  tdata = get_options_test_data("SafeLogging stuffy\n"
                                "MaxClientCircuitsPending 1\n"
                                "ConnLimit 1\n"
                                "SchedulerHighWaterMark__ 42\n"
                                "SchedulerLowWaterMark__ 10\n");

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Unrecognized value '\"stuffy\"' in SafeLogging");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__publish_server_descriptor(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);
  options_test_data_t *tdata = get_options_test_data("PublishServerDescriptor bridge\n" TEST_OPTIONS_DEFAULT_VALUES);

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_assert(!msg);

  free_options_test_data(tdata);
  tdata = get_options_test_data("PublishServerDescriptor humma\n" TEST_OPTIONS_DEFAULT_VALUES);

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Unrecognized value in PublishServerDescriptor");

  free_options_test_data(tdata);
  tdata = get_options_test_data("PublishServerDescriptor bridge, v3\n" TEST_OPTIONS_DEFAULT_VALUES);

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Bridges are not supposed to publish router descriptors to the directory authorities. Please correct your PublishServerDescriptor line.");

  free_options_test_data(tdata);
  tdata = get_options_test_data("BridgeRelay 1\n"
                                "PublishServerDescriptor v3\n" TEST_OPTIONS_DEFAULT_VALUES);

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Bridges are not supposed to publish router descriptors to the directory authorities. Please correct your PublishServerDescriptor line.");


  free_options_test_data(tdata);
  tdata = get_options_test_data("BridgeRelay 1\n" TEST_OPTIONS_DEFAULT_VALUES);

  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_NE, "Bridges are not supposed to publish router descriptors to the directory authorities. Please correct your PublishServerDescriptor line.");


  free_options_test_data(tdata);
  tdata = get_options_test_data("BridgeRelay 1\n"
                                "DirPort 999\n" TEST_OPTIONS_DEFAULT_VALUES);

  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "Can't set a DirPort on a bridge relay; disabling DirPort\n");
  tt_assert(!tdata->opt->DirPort_lines);
  tt_assert(!tdata->opt->DirPort_set);

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__testing(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = NULL;

#define ENSURE_DEFAULT(varname, varval)                     \
  STMT_BEGIN                                                \
    free_options_test_data(tdata);                          \
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES \
                                #varname " " #varval "\n"); \
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); \
  tt_str_op(msg, OP_EQ, #varname " may only be changed in testing Tor networks!"); \
  tt_int_op(ret, OP_EQ, -1);                                            \
                                                                        \
  free_options_test_data(tdata); \
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES \
                                #varname " " #varval "\n"               \
                                "DirAuthority dizum orport=443 v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 194.109.206.212:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755\n" \
                                "TestingTorNetwork 1\n");               \
                                                                        \
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); \
  if(msg) { \
    tt_str_op(msg, OP_NE, #varname " may only be changed in testing Tor networks!"); \
  } \
                                                                        \
  free_options_test_data(tdata);          \
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES \
                                #varname " " #varval "\n"           \
                                "___UsingTestNetworkDefaults 1\n"); \
                                                                        \
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); \
  if(msg) { \
    tt_str_op(msg, OP_NE, #varname " may only be changed in testing Tor networks!"); \
  } \
    STMT_END

  ENSURE_DEFAULT(TestingV3AuthInitialVotingInterval, 3600);
  ENSURE_DEFAULT(TestingV3AuthInitialVoteDelay, 3000);
  ENSURE_DEFAULT(TestingV3AuthInitialDistDelay, 3000);
  ENSURE_DEFAULT(TestingV3AuthVotingStartOffset, 3000);
  ENSURE_DEFAULT(TestingAuthDirTimeToLearnReachability, 3000);
  ENSURE_DEFAULT(TestingEstimatedDescriptorPropagationTime, 3000);
  ENSURE_DEFAULT(TestingServerDownloadSchedule, 3000);
  ENSURE_DEFAULT(TestingClientDownloadSchedule, 3000);
  ENSURE_DEFAULT(TestingServerConsensusDownloadSchedule, 3000);
  ENSURE_DEFAULT(TestingClientConsensusDownloadSchedule, 3000);
  ENSURE_DEFAULT(TestingBridgeDownloadSchedule, 3000);
  ENSURE_DEFAULT(TestingClientMaxIntervalWithoutRequest, 3000);
  ENSURE_DEFAULT(TestingDirConnectionMaxStall, 3000);
  ENSURE_DEFAULT(TestingConsensusMaxDownloadTries, 3000);
  ENSURE_DEFAULT(TestingDescriptorMaxDownloadTries, 3000);
  ENSURE_DEFAULT(TestingMicrodescMaxDownloadTries, 3000);
  ENSURE_DEFAULT(TestingCertMaxDownloadTries, 3000);
  ENSURE_DEFAULT(TestingAuthKeyLifetime, 3000);
  ENSURE_DEFAULT(TestingLinkCertLifetime, 3000);
  ENSURE_DEFAULT(TestingSigningKeySlop, 3000);
  ENSURE_DEFAULT(TestingAuthKeySlop, 3000);
  ENSURE_DEFAULT(TestingLinkKeySlop, 3000);

  // TODO: TestingV3AuthInitialVotingInterval seems to check for division by 30 minutes incorrectly

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__hidserv(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);

  options_test_data_t *tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES);
  tdata->opt->MinUptimeHidServDirectoryV2 = -1;
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "MinUptimeHidServDirectoryV2 option must be at least 0 seconds. Changing to 0.\n");
  tt_int_op(tdata->opt->MinUptimeHidServDirectoryV2, OP_EQ, 0);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "RendPostPeriod 1\n" );
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "RendPostPeriod option is too short; raising to 600 seconds.\n");
  tt_int_op(tdata->opt->RendPostPeriod, OP_EQ, 600);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "RendPostPeriod 302401\n" );
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "RendPostPeriod is too large; clipping to 302400s.\n");
  tt_int_op(tdata->opt->RendPostPeriod, OP_EQ, 302400);

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__predicted_ports(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  int previous_log = setup_capture_of_logs(LOG_WARN);

  options_test_data_t *tdata = get_options_test_data("PredictedPortsRelevanceTime 100000000\n" TEST_OPTIONS_DEFAULT_VALUES);
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "PredictedPortsRelevanceTime is too large; clipping to 3600s.\n");
  tt_int_op(tdata->opt->PredictedPortsRelevanceTime, OP_EQ, 3600);

  //  free_options_test_data(tdata);

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__path_bias(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;

  options_test_data_t *tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PathBiasNoticeRate 1.1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PathBiasNoticeRate is too high. It must be between 0 and 1.0");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PathBiasWarnRate 1.1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PathBiasWarnRate is too high. It must be between 0 and 1.0");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PathBiasExtremeRate 1.1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PathBiasExtremeRate is too high. It must be between 0 and 1.0");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PathBiasNoticeUseRate 1.1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PathBiasNoticeUseRate is too high. It must be between 0 and 1.0");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PathBiasExtremeUseRate 1.1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PathBiasExtremeUseRate is too high. It must be between 0 and 1.0");

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__bandwidth(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = NULL;

#define ENSURE_BANDWIDTH_PARAM(p) \
  STMT_BEGIN                                                \
  free_options_test_data(tdata); \
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES #p " 3Gb\n"); \
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg); \
  tt_int_op(ret, OP_EQ, -1); \
  tt_mem_op(msg, OP_EQ, #p " (3221225471) must be at most 2147483647", 40); \
  STMT_END

  ENSURE_BANDWIDTH_PARAM(BandwidthRate);
  ENSURE_BANDWIDTH_PARAM(BandwidthBurst);
  ENSURE_BANDWIDTH_PARAM(MaxAdvertisedBandwidth);
  ENSURE_BANDWIDTH_PARAM(RelayBandwidthRate);
  ENSURE_BANDWIDTH_PARAM(RelayBandwidthBurst);
  ENSURE_BANDWIDTH_PARAM(PerConnBWRate);
  ENSURE_BANDWIDTH_PARAM(PerConnBWBurst);
  ENSURE_BANDWIDTH_PARAM(AuthDirFastGuarantee);
  ENSURE_BANDWIDTH_PARAM(AuthDirGuardBWGuarantee);


  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "RelayBandwidthRate 1000\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(tdata->opt->RelayBandwidthBurst, OP_EQ, 1000);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "RelayBandwidthBurst 1001\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(tdata->opt->RelayBandwidthRate, OP_EQ, 1001);


  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "RelayBandwidthRate 1001\n"
                                "RelayBandwidthBurst 1000\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "RelayBandwidthBurst must be at least equal to RelayBandwidthRate.");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "BandwidthRate 1001\n"
                                "BandwidthBurst 1000\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "BandwidthBurst must be at least equal to BandwidthRate.");


  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "RelayBandwidthRate 1001\n"
                                "BandwidthRate 1000\n"
                                "BandwidthBurst 1000\n"
                                );
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(tdata->opt->BandwidthRate, OP_EQ, 1001);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "RelayBandwidthRate 1001\n"
                                "BandwidthRate 1000\n"
                                "RelayBandwidthBurst 1001\n"
                                "BandwidthBurst 1000\n"
                                );
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_int_op(tdata->opt->BandwidthBurst, OP_EQ, 1001);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__circuits(void *ignored)
{
  (void)ignored;
  char *msg;
  options_test_data_t *tdata = NULL;
  int previous_log = setup_capture_of_logs(LOG_WARN);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "MaxCircuitDirtiness 2592001\n");
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "MaxCircuitDirtiness option is too high; setting to 30 days.\n");
  tt_int_op(tdata->opt->MaxCircuitDirtiness, OP_EQ, 2592000);

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "CircuitStreamTimeout 1\n");
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(2), OP_EQ, "CircuitStreamTimeout option is too short; raising to 10 seconds.\n");
  tt_int_op(tdata->opt->CircuitStreamTimeout, OP_EQ, 10);

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "CircuitStreamTimeout 111\n");
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(2), OP_NE, "CircuitStreamTimeout option is too short; raising to 10 seconds.\n");
  tt_int_op(tdata->opt->CircuitStreamTimeout, OP_EQ, 111);

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "HeartbeatPeriod 1\n");
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(2), OP_EQ, "HeartbeatPeriod option is too short; raising to 1800 seconds.\n");
  tt_int_op(tdata->opt->HeartbeatPeriod, OP_EQ, 1800);

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "HeartbeatPeriod 1982\n");
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(2), OP_NE, "HeartbeatPeriod option is too short; raising to 1800 seconds.\n");
  tt_int_op(tdata->opt->HeartbeatPeriod, OP_EQ, 1982);

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "CircuitBuildTimeout 1\n"
                                );
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "CircuitBuildTimeout is shorter (1 seconds) than the recommended minimum (10 seconds), and LearnCircuitBuildTimeout is disabled.  If tor isn't working, raise this value or enable LearnCircuitBuildTimeout.\n");

  free_options_test_data(tdata);
  mock_clean_saved_logs();
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "CircuitBuildTimeout 11\n"
                                );
  options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_str_op(mock_saved_log_at(1), OP_NE, "CircuitBuildTimeout is shorter (1 seconds) than the recommended minimum (10 seconds), and LearnCircuitBuildTimeout is disabled.  If tor isn't working, raise this value or enable LearnCircuitBuildTimeout.\n");

 done:
  teardown_capture_of_logs(previous_log);
  free_options_test_data(tdata);
  tor_free(msg);
}

static void
test_options_validate__port_forwarding(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = NULL;

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PortForwarding 1\nSandbox 1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "PortForwarding is not compatible with Sandbox; at most one can be set");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "PortForwarding 1\nSandbox 0\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_assert(!msg);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__tor2web(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = NULL;

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "Tor2webRendezvousPoints 1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, -1);
  tt_str_op(msg, OP_EQ, "Tor2webRendezvousPoints cannot be set without Tor2webMode.");

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES "Tor2webRendezvousPoints 1\nTor2webMode 1\n");
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);

 done:
  free_options_test_data(tdata);
  tor_free(msg);
}


static void
test_options_validate__rend(void *ignored)
{
  (void)ignored;
  int ret;
  char *msg;
  options_test_data_t *tdata = NULL;
  int previous_log = setup_capture_of_logs(LOG_WARN);

  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "UseEntryGuards 0\n"
                                "HiddenServiceDir /Library/Tor/var/lib/tor/hidden_service/\n"
                                "HiddenServicePort 80 127.0.0.1:8080\n"
                                );
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_EQ, "UseEntryGuards is disabled, but you have configured one or more hidden services on this Tor instance.  Your hidden services will be very easy to locate using a well-known attack -- see http://freehaven.net/anonbib/#hs-attack06 for details.\n");


  free_options_test_data(tdata);
  tdata = get_options_test_data(TEST_OPTIONS_DEFAULT_VALUES
                                "UseEntryGuards 1\n"
                                "HiddenServiceDir /Library/Tor/var/lib/tor/hidden_service/\n"
                                "HiddenServicePort 80 127.0.0.1:8080\n"
                                );
  mock_clean_saved_logs();
  ret = options_validate(tdata->old_opt, tdata->opt, tdata->def_opt, 0, &msg);
  tt_int_op(ret, OP_EQ, 0);
  tt_str_op(mock_saved_log_at(1), OP_NE, "UseEntryGuards is disabled, but you have configured one or more hidden services on this Tor instance.  Your hidden services will be very easy to locate using a well-known attack -- see http://freehaven.net/anonbib/#hs-attack06 for details.\n");

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
  { "validate__fetch_dir", test_options_validate__fetch_dir, TT_FORK, NULL, NULL },
  { "validate__conn_limit", test_options_validate__conn_limit, TT_FORK, NULL, NULL },
  { "validate__paths_needed", test_options_validate__paths_needed, TT_FORK, NULL, NULL },
  { "validate__max_client_circuits", test_options_validate__max_client_circuits, TT_FORK, NULL, NULL },
  { "validate__ports", test_options_validate__ports, TT_FORK, NULL, NULL },
  { "validate__reachable_addresses", test_options_validate__reachable_addresses, TT_FORK, NULL, NULL },
  { "validate__use_bridges", test_options_validate__use_bridges, TT_FORK, NULL, NULL },
  { "validate__entry_nodes", test_options_validate__entry_nodes, TT_FORK, NULL, NULL },
  { "validate__invalid_nodes", test_options_validate__invalid_nodes, TT_FORK, NULL, NULL },
  { "validate__safe_logging", test_options_validate__safe_logging, TT_FORK, NULL, NULL },
  { "validate__publish_server_descriptor", test_options_validate__publish_server_descriptor, TT_FORK, NULL, NULL },
  { "validate__testing", test_options_validate__testing, TT_FORK, NULL, NULL },
  { "validate__hidserv", test_options_validate__hidserv, TT_FORK, NULL, NULL },
  { "validate__predicted_ports", test_options_validate__predicted_ports, TT_FORK, NULL, NULL },
  { "validate__path_bias", test_options_validate__path_bias, TT_FORK, NULL, NULL },
  { "validate__bandwidth", test_options_validate__bandwidth, TT_FORK, NULL, NULL },
  { "validate__circuits", test_options_validate__circuits, TT_FORK, NULL, NULL },
  { "validate__port_forwarding", test_options_validate__port_forwarding, TT_FORK, NULL, NULL },
  { "validate__tor2web", test_options_validate__tor2web, TT_FORK, NULL, NULL },
  { "validate__rend", test_options_validate__rend, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
