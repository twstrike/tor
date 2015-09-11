/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define RENDCOMMON_PRIVATE
#define GEOIP_PRIVATE

#include "or.h"
#include "config.h"
#include "directory.h"
#include "test.h"
#include "connection.h"
#include "rendcommon.h"
#include "rendcache.h"
#include "router.h"
#include "routerlist.h"
#include "rend_test_helpers.h"
#include "microdesc.h"
#include "test_helpers.h"
#include "nodelist.h"
#include "entrynodes.h"
#include "routerparse.h"
#include "networkstatus.h"
#include "geoip.h"
#include "dirserv.h"
#include "torgzip.h"
#include "dirvote.h"

#ifdef _WIN32
/* For mkdir() */
#include <direct.h>
#else
#include <dirent.h>
#endif

#define NS_MODULE dir_client_reached_eof

static tor_addr_t MOCK_TOR_ADDR;

static void
test_dir_client_reached_eof_not_found(void *data)
{
  dir_connection_t *conn = NULL;
  (void) data;


  conn = dir_connection_new(tor_addr_family(&MOCK_TOR_ADDR));

  tt_int_op(connection_dir_client_reached_eof(conn), OP_EQ, -1);

  done:
    tor_free(conn);
}


#define DIR_CLIENT_REACHED_EOF_CMD(name,flags) \
  { #name, test_dir_client_reached_eof_##name, (flags), NULL, NULL }

struct testcase_t dir_client_reached_eof_tests[] = {
  DIR_CLIENT_REACHED_EOF_CMD(not_found, 0),
  END_OF_TESTCASES
};
