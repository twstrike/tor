/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "test.h"
#define RENDCACHE_PRIVATE
#include "rendcache.h"
#include "router.h"
#include "routerlist.h"
#include "config.h"

#define NS_MODULE rend_cache

static const int RECENT_TIME = -10;
static const int TIME_IN_THE_PAST = -(REND_CACHE_MAX_AGE + REND_CACHE_MAX_SKEW + 10);
static const int TIME_IN_THE_FUTURE = REND_CACHE_MAX_SKEW + 10;

extern strmap_t *rend_cache;
extern digestmap_t *rend_cache_v2_dir;
extern strmap_t *rend_cache_failure;
extern size_t rend_cache_total_allocation;

static rend_data_t
mock_rend_data(char *onion_address)
{
  rend_data_t rend_query;

  memset(&rend_query, 0, sizeof(rend_query));
  strncpy(rend_query.onion_address, onion_address, REND_SERVICE_ID_LEN_BASE32+1);
  rend_query.auth_type = REND_NO_AUTH;
  rend_query.hsdirs_fp = smartlist_new();
  smartlist_add(rend_query.hsdirs_fp, tor_memdup("aaaaaaaaaaaaaaaaaaaaaaaa", DIGEST_LEN));

  return rend_query;
}

static void
create_descriptor(rend_service_descriptor_t **generated, char **service_id)
{
  crypto_pk_t *pk1 = NULL;
  crypto_pk_t *pk2 = NULL;
  int i;

  *service_id = tor_malloc(REND_SERVICE_ID_LEN_BASE32+1);
  pk1 = pk_generate(0);
  pk2 = pk_generate(1);

  *generated = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  (*generated)->pk = crypto_pk_dup_key(pk1);
  rend_get_service_id((*generated)->pk, *service_id);

  (*generated)->version = 2;
  (*generated)->protocols = 42;
  (*generated)->intro_nodes = smartlist_new();

  for (i = 0; i < 3; i++) {
    rend_intro_point_t *intro = tor_malloc_zero(sizeof(rend_intro_point_t));
    crypto_pk_t *okey = pk_generate(2 + i);
    intro->extend_info = tor_malloc_zero(sizeof(extend_info_t));
    intro->extend_info->onion_key = okey;
    crypto_pk_get_digest(intro->extend_info->onion_key,
                         intro->extend_info->identity_digest);
    intro->extend_info->nickname[0] = '$';
    base16_encode(intro->extend_info->nickname + 1,
                  sizeof(intro->extend_info->nickname) - 1,
                  intro->extend_info->identity_digest, DIGEST_LEN);
    tor_addr_from_ipv4h(&intro->extend_info->addr, crypto_rand_int(65536));
    intro->extend_info->port = 1 + crypto_rand_int(65535);
    intro->intro_key = crypto_pk_dup_key(pk2);
    smartlist_add((*generated)->intro_nodes, intro);
  }

  crypto_pk_free(pk1);
  crypto_pk_free(pk2);
}

static void
generate_desc(int time_diff, rend_encoded_v2_service_descriptor_t **desc, char **service_id)
{
  rend_service_descriptor_t *generated = NULL;
  smartlist_t *descs = smartlist_new();
  time_t now;

  now = time(NULL) + time_diff;
  create_descriptor(&generated, service_id);
  generated->timestamp = now;

  rend_encode_v2_descriptors(descs, generated, now, 0, REND_NO_AUTH, NULL, NULL);
  *desc = ((rend_encoded_v2_service_descriptor_t *)smartlist_get(descs, 0));

  smartlist_free(descs);
  rend_service_descriptor_free(generated);
}

static void
test_rend_cache_lookup_entry(void *data)
{
  int ret;
  rend_data_t mock_rend_query;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  rend_cache_entry_t *entry = NULL;
  rend_encoded_v2_service_descriptor_t *desc_holder;
  char *service_id = NULL;
  (void)data;

  rend_cache_init();

  generate_desc(RECENT_TIME, &desc_holder, &service_id);


  ret = rend_cache_lookup_entry("abababababababab", 0, NULL);
  tt_int_op(ret, OP_EQ, -ENOENT);

  ret = rend_cache_lookup_entry("invalid query", 2, NULL);
  tt_int_op(ret, OP_EQ, -EINVAL);

  ret = rend_cache_lookup_entry("abababababababab", 2, NULL);
  tt_int_op(ret, OP_EQ, -ENOENT);

  ret = rend_cache_lookup_entry("abababababababab", 4224, NULL);
  tt_int_op(ret, OP_EQ, -ENOENT);

  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);
  rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);

  ret = rend_cache_lookup_entry(service_id, 2, NULL);
  tt_int_op(ret, OP_EQ, 0);

  ret = rend_cache_lookup_entry(service_id, 2, &entry);
  tt_assert(entry);
  tt_int_op(entry->len, OP_EQ, strlen(desc_holder->desc_str));
  tt_str_op(entry->desc, OP_EQ, desc_holder->desc_str);

 done:
  tor_free(desc_holder);
  tor_free(entry);
  tor_free(service_id);
}

static void
test_rend_cache_store_v2_desc_as_client(void *data)
{
  rend_cache_store_status_t ret;
  rend_data_t mock_rend_query;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  rend_cache_entry_t *entry = NULL;
  rend_encoded_v2_service_descriptor_t *desc_holder;
  char *service_id = NULL;
  (void)data;

  rend_cache_init();

  generate_desc(RECENT_TIME, &desc_holder, &service_id);

  // Test success
  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);
  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, &entry);

  tt_int_op(ret, OP_EQ, RCS_OKAY);
  tt_assert(entry);
  tt_int_op(entry->len, OP_EQ, strlen(desc_holder->desc_str));
  tt_str_op(entry->desc, OP_EQ, desc_holder->desc_str);


  // Test various failure modes

  // TODO: a too long desc_id_base32 argument crashes the function
  /* ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, "3TOOLONG3TOOLONG3TOOLONG3TOOLONG3TOOLONG3TOOLONG", &mock_rend_query, NULL); */
  /* tt_int_op(ret, OP_EQ, RCS_BADDESC); */

  // Test bad base32 failure
  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, "!xqunszqnaolrrfmtzgaki7mxelgvkj", &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);

  // Test invalid descriptor
  ret = rend_cache_store_v2_desc_as_client("invalid descriptor", "3xqunszqnaolrrfmtzgaki7mxelgvkje", &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);

  // TODO: it doesn't seem to be possible to test invalid service ID condition.
  // that means it is likely not possible to have that condition without earlier conditions failing first (such as signature checking of the desc)

  // Test mismatch between service ID and onion address
  rend_cache_init();
  strncpy(mock_rend_query.onion_address, "abc", REND_SERVICE_ID_LEN_BASE32+1);
  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);

  // Test incorrect descriptor ID
  rend_cache_init();
  mock_rend_query = mock_rend_data(service_id);
  desc_id_base32[0]++;
  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);
  desc_id_base32[0]--;

  // Test too old descriptor
  rend_cache_init();
  tor_free(desc_holder);
  tor_free(service_id);

  generate_desc(TIME_IN_THE_PAST, &desc_holder, &service_id);
  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);

  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);

  // Test too new descriptor (in the future)
  rend_cache_init();
  tor_free(desc_holder);
  tor_free(service_id);

  generate_desc(TIME_IN_THE_FUTURE, &desc_holder, &service_id);
  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);

  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_BADDESC);

  // Test when a descriptor is already in the cache
  rend_cache_init();
  tor_free(desc_holder);
  tor_free(service_id);
  tor_free(entry);

  generate_desc(RECENT_TIME, &desc_holder, &service_id);
  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);

  rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_OKAY);

  ret = rend_cache_store_v2_desc_as_client(desc_holder->desc_str, desc_id_base32, &mock_rend_query, &entry);
  tt_int_op(ret, OP_EQ, RCS_OKAY);
  tt_assert(entry);

 done:
  rend_encoded_v2_service_descriptor_free(desc_holder);
  tor_free(entry);
  tor_free(service_id);
}

static void
test_rend_cache_store_v2_desc_as_client_with_different_time(void *data)
{
  rend_cache_store_status_t ret;
  rend_data_t mock_rend_query;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  rend_service_descriptor_t *generated = NULL;
  smartlist_t *descs = smartlist_new();
  time_t t;
  char *service_id = NULL;
  rend_encoded_v2_service_descriptor_t *desc_holder_newer;
  rend_encoded_v2_service_descriptor_t *desc_holder_older;

  t = time(NULL);

  create_descriptor(&generated, &service_id);

  generated->timestamp = t + RECENT_TIME;
  rend_encode_v2_descriptors(descs, generated, t + RECENT_TIME, 0, REND_NO_AUTH, NULL, NULL);
  desc_holder_newer = ((rend_encoded_v2_service_descriptor_t *)smartlist_get(descs, 0));

  smartlist_free(descs);
  descs = smartlist_new();

  generated->timestamp = (t + RECENT_TIME) - 20;
  rend_encode_v2_descriptors(descs, generated, t + RECENT_TIME, 0, REND_NO_AUTH, NULL, NULL);
  desc_holder_older = ((rend_encoded_v2_service_descriptor_t *)smartlist_get(descs, 0));

  (void)data;
  rend_cache_init();

  // Test when a descriptor is already in the cache and it is newer than the one we submit
  mock_rend_query = mock_rend_data(service_id);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder_newer->desc_id, DIGEST_LEN);
  rend_cache_store_v2_desc_as_client(desc_holder_newer->desc_str, desc_id_base32, &mock_rend_query, NULL);
  ret = rend_cache_store_v2_desc_as_client(desc_holder_older->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_OKAY);

  // Test when an old descriptor is in the cache and we submit a newer one
  rend_cache_init();
  rend_cache_store_v2_desc_as_client(desc_holder_older->desc_str, desc_id_base32, &mock_rend_query, NULL);
  ret = rend_cache_store_v2_desc_as_client(desc_holder_newer->desc_str, desc_id_base32, &mock_rend_query, NULL);
  tt_int_op(ret, OP_EQ, RCS_OKAY);

 done:
  rend_encoded_v2_service_descriptor_free(desc_holder_newer);
  rend_encoded_v2_service_descriptor_free(desc_holder_older);
  smartlist_free(descs);
  rend_service_descriptor_free(generated);
  tor_free(service_id);
}


#define NS_SUBMODULE lookup_v2_desc_as_dir
NS_DECL(const routerinfo_t *, router_get_my_routerinfo, (void));
NS_DECL(int, hid_serv_responsible_for_desc_id, (const char *id));

static routerinfo_t *mock_routerinfo;
static int hid_serv_responsible_for_desc_id_response;

static const routerinfo_t *
NS(router_get_my_routerinfo)(void)
{
  if(!mock_routerinfo) {
    mock_routerinfo = tor_malloc(sizeof(routerinfo_t));
  }

  return mock_routerinfo;
}

static int
NS(hid_serv_responsible_for_desc_id)(const char *id)
{
  return hid_serv_responsible_for_desc_id_response;
}

static void
test_rend_cache_lookup_v2_desc_as_dir(void *data)
{
  int ret;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
  rend_encoded_v2_service_descriptor_t *desc_holder;
  char *service_id = NULL;
  const char *ret_desc = NULL;

  (void)data;

  NS_MOCK(router_get_my_routerinfo);
  NS_MOCK(hid_serv_responsible_for_desc_id);

  rend_cache_init();

  // Test invalid base32
  ret = rend_cache_lookup_v2_desc_as_dir("!bababababababab", NULL);
  tt_int_op(ret, OP_EQ, -1);

  // Test non-existent descriptor but well formed
  ret = rend_cache_lookup_v2_desc_as_dir("3xqunszqnaolrrfmtzgaki7mxelgvkje", NULL);
  tt_int_op(ret, OP_EQ, 0);

  // Test existing descriptor
  hid_serv_responsible_for_desc_id_response = 1;
  generate_desc(RECENT_TIME, &desc_holder, &service_id);
  rend_cache_store_v2_desc_as_dir(desc_holder->desc_str);
  base32_encode(desc_id_base32, sizeof(desc_id_base32), desc_holder->desc_id, DIGEST_LEN);
  ret = rend_cache_lookup_v2_desc_as_dir(desc_id_base32, &ret_desc);
  tt_int_op(ret, OP_EQ, 1);
  tt_assert(ret_desc);

 done:
  NS_UNMOCK(router_get_my_routerinfo);
  NS_UNMOCK(hid_serv_responsible_for_desc_id);
  tor_free(mock_routerinfo);
}

#undef NS_SUBMODULE

static void
test_rend_cache_init(void *data)
{
  (void)data;

  tt_assert_msg(!rend_cache, "rend_cache should be NULL when starting");
  tt_assert_msg(!rend_cache_v2_dir, "rend_cache_v2_dir should be NULL when starting");
  tt_assert_msg(!rend_cache_failure, "rend_cache_failure should be NULL when starting");

  rend_cache_init();

  tt_assert_msg(rend_cache, "rend_cache should not be NULL after initing");
  tt_assert_msg(rend_cache_v2_dir, "rend_cache_v2_dir should not be NULL after initing");
  tt_assert_msg(rend_cache_failure, "rend_cache_failure should not be NULL after initing");

  tt_int_op(strmap_size(rend_cache), OP_EQ, 0);
  tt_int_op(digestmap_size(rend_cache_v2_dir), OP_EQ, 0);
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 0);

 done:
  (void)0;
}

static void
test_rend_cache_decrement_allocation(void *data)
{
  (void)data;

  // Test when the cache has enough allocations
  rend_cache_total_allocation = 10;
  rend_cache_decrement_allocation(3);
  tt_int_op(rend_cache_total_allocation, OP_EQ, 7);

  // Test when there are not enough allocations
  rend_cache_total_allocation = 1;
  rend_cache_decrement_allocation(2);
  tt_int_op(rend_cache_total_allocation, OP_EQ, 0);

  // And again
  rend_cache_decrement_allocation(2);
  tt_int_op(rend_cache_total_allocation, OP_EQ, 0);

 done:
  (void)0;
}

static void
test_rend_cache_increment_allocation(void *data)
{
  (void)data;

  // Test when the cache is not overflowing
  rend_cache_total_allocation = 5;
  rend_cache_increment_allocation(3);
  tt_int_op(rend_cache_total_allocation, OP_EQ, 8);

  // Test when there are too many allocations
  rend_cache_total_allocation = SIZE_MAX-1;
  rend_cache_increment_allocation(2);
  tt_int_op(rend_cache_total_allocation, OP_EQ, SIZE_MAX);

  // And again
  rend_cache_increment_allocation(2);
  tt_int_op(rend_cache_total_allocation, OP_EQ, SIZE_MAX);

 done:
  (void)0;
}


static void
test_rend_cache_failure_intro_entry_new(void *data)
{
  time_t now;
  rend_cache_failure_intro_t *entry;
  rend_intro_point_failure_t failure;

  (void)data;

  failure = INTRO_POINT_FAILURE_TIMEOUT;
  now = time(NULL);
  entry = rend_cache_failure_intro_entry_new(failure);

  tt_int_op(entry->failure_type, OP_EQ, INTRO_POINT_FAILURE_TIMEOUT);
  tt_int_op(entry->created_ts, OP_GE, now-5);
  tt_int_op(entry->created_ts, OP_LE, now+5);

 done:
  tor_free(entry);
}

static void
test_rend_cache_clean(void *data)
{
  rend_cache_entry_t *one, *two;
  rend_service_descriptor_t *desc_one, *desc_two;
  strmap_iter_t *iter = NULL;
  const char *key;
  void *val;

  (void)data;

  rend_cache_init();

  // Test with empty rendcache
  rend_cache_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache), OP_EQ, 0);

  // Test with two old entries
  one = tor_malloc_zero(sizeof(rend_cache_entry_t));
  two = tor_malloc_zero(sizeof(rend_cache_entry_t));
  desc_one = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  desc_two = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  one->parsed = desc_one;
  two->parsed = desc_two;

  desc_one->timestamp = time(NULL) + TIME_IN_THE_PAST;
  desc_two->timestamp = (time(NULL) + TIME_IN_THE_PAST) - 10;
  desc_one->pk = pk_generate(0);
  desc_two->pk = pk_generate(1);

  strmap_set_lc(rend_cache, "foo1", one);
  strmap_set_lc(rend_cache, "foo2", two);

  rend_cache_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache), OP_EQ, 0);

  // Test with one old entry and one newer entry
  one = tor_malloc_zero(sizeof(rend_cache_entry_t));
  two = tor_malloc_zero(sizeof(rend_cache_entry_t));
  desc_one = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  desc_two = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  one->parsed = desc_one;
  two->parsed = desc_two;

  desc_one->timestamp = (time(NULL) + TIME_IN_THE_PAST) - 10;
  desc_two->timestamp = time(NULL) - 100;
  desc_one->pk = pk_generate(0);
  desc_two->pk = pk_generate(1);

  strmap_set_lc(rend_cache, "foo1", one);
  strmap_set_lc(rend_cache, "foo2", two);

  rend_cache_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache), OP_EQ, 1);

  iter = strmap_iter_init(rend_cache);
  strmap_iter_get(iter, &key, &val);
  tt_str_op(key, OP_EQ, "foo2");

 done:
  (void)1;
}

static void
test_rend_cache_failure_entry_new(void *data)
{
  rend_cache_failure_t *failure;

  (void)data;

  failure = rend_cache_failure_entry_new();
  tt_assert(failure);
  tt_int_op(digestmap_size(failure->intro_failures), OP_EQ, 0);

 done:
  tor_free(failure);
}

static void
test_rend_cache_failure_clean(void *data)
{
  rend_cache_failure_t *failure;
  rend_cache_failure_intro_t *ip_one, *ip_two;

  (void)data;

  rend_cache_init();

  // Test with empty failure cache
  rend_cache_failure_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 0);

  // Test with one empty failure entry
  failure = rend_cache_failure_entry_new();
  strmap_set_lc(rend_cache_failure, "foo1", failure);
  rend_cache_failure_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 0);

  // Test with one new intro point
  failure = rend_cache_failure_entry_new();
  ip_one = rend_cache_failure_intro_entry_new(INTRO_POINT_FAILURE_TIMEOUT);
  digestmap_set(failure->intro_failures, "ip1", ip_one);
  strmap_set_lc(rend_cache_failure, "foo1", failure);
  rend_cache_failure_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 1);

  // Test with one old intro point
  rend_cache_failure_purge();
  failure = rend_cache_failure_entry_new();
  ip_one = rend_cache_failure_intro_entry_new(INTRO_POINT_FAILURE_TIMEOUT);
  ip_one->created_ts = time(NULL) - 7*60;
  digestmap_set(failure->intro_failures, "ip1", ip_one);
  strmap_set_lc(rend_cache_failure, "foo1", failure);
  rend_cache_failure_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 0);


  // Test with one old intro point and one new one
  rend_cache_failure_purge();
  failure = rend_cache_failure_entry_new();
  ip_one = rend_cache_failure_intro_entry_new(INTRO_POINT_FAILURE_TIMEOUT);
  ip_one->created_ts = time(NULL) - 7*60;
  digestmap_set(failure->intro_failures, "ip1", ip_one);
  ip_two = rend_cache_failure_intro_entry_new(INTRO_POINT_FAILURE_TIMEOUT);
  ip_two->created_ts = time(NULL) - 2*60;
  digestmap_set(failure->intro_failures, "ip2", ip_two);
  strmap_set_lc(rend_cache_failure, "foo1", failure);
  rend_cache_failure_clean(time(NULL));
  tt_int_op(strmap_size(rend_cache_failure), OP_EQ, 1);
  tt_int_op(digestmap_size(failure->intro_failures), OP_EQ, 1);

 done:
  (void)0;
}


static void
test_rend_cache_failure_remove(void *data)
{
  rend_service_descriptor_t *desc;
  (void)data;

  rend_cache_init();

  // Test that it deals well with a NULL desc
  rend_cache_failure_remove(NULL);

  // Test a descriptor that isn't in the cache
  desc = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  desc->pk = pk_generate(0);
  rend_cache_failure_remove(desc);

 /* done: */
 /*  (void)0; */
}

static void
test_rend_cache_free_all(void *data)
{
  rend_cache_failure_t *failure;
  rend_cache_entry_t *one;
  rend_service_descriptor_t *desc_one;

  (void)data;

  rend_cache_init();

  failure = rend_cache_failure_entry_new();
  strmap_set_lc(rend_cache_failure, "foo1", failure);

  one = tor_malloc_zero(sizeof(rend_cache_entry_t));
  desc_one = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  one->parsed = desc_one;
  desc_one->timestamp = time(NULL) + TIME_IN_THE_PAST;
  desc_one->pk = pk_generate(0);
  strmap_set_lc(rend_cache, "foo1", one);

  rend_cache_free_all();

  tt_assert(!rend_cache);
  tt_assert(!rend_cache_v2_dir);
  tt_assert(!rend_cache_failure);
  tt_assert(!rend_cache_total_allocation);

 done:
  (void)0;
}


static void
test_rend_cache_purge(void *data)
{
  strmap_t *our_rend_cache;

  (void)data;

  // Deals with a NULL rend_cache
  rend_cache_purge();
  tt_assert(rend_cache);
  tt_int_op(strmap_size(rend_cache), OP_EQ, 0);

  // Deals with existing rend_cache
  rend_cache_init();

  our_rend_cache = rend_cache;
  rend_cache_purge();
  tt_assert(rend_cache);
  tt_assert(rend_cache == our_rend_cache);

 done:
  (void)0;
}

static void
test_rend_cache_failure_intro_add(void *data)
{
  (void)data;
  rend_cache_failure_t *fail_entry;
  rend_cache_failure_intro_t *entry;

  rend_cache_init();

  cache_failure_intro_add((const uint8_t *)"foo1", "foo2", INTRO_POINT_FAILURE_TIMEOUT);
  fail_entry = strmap_get_lc(rend_cache_failure, "foo2");
  tt_assert(fail_entry);
  tt_int_op(digestmap_size(fail_entry->intro_failures), OP_EQ, 1);
  entry = digestmap_get(fail_entry->intro_failures, "foo1");
  tt_assert(entry);

 done:
  rend_cache_purge();
}


static void
test_rend_cache_intro_failure_note(void *data)
{
  (void)data;
  rend_cache_failure_t *fail_entry;
  rend_cache_failure_intro_t *entry;

  // Test not found
  rend_cache_intro_failure_note(INTRO_POINT_FAILURE_TIMEOUT,(const uint8_t *)"foo1", "foo2");
  fail_entry = strmap_get_lc(rend_cache_failure, "foo2");
  tt_assert(fail_entry);
  tt_int_op(digestmap_size(fail_entry->intro_failures), OP_EQ, 1);
  entry = digestmap_get(fail_entry->intro_failures, "foo1");
  tt_assert(entry);
  tt_int_op(entry->failure_type, OP_EQ, INTRO_POINT_FAILURE_TIMEOUT);

  // Test found
  rend_cache_intro_failure_note(INTRO_POINT_FAILURE_UNREACHABLE,(const uint8_t *)"foo1", "foo2");
  tt_int_op(entry->failure_type, OP_EQ, INTRO_POINT_FAILURE_UNREACHABLE);

 done:
  rend_cache_purge();
}

#define NS_SUBMODULE clean_v2_descs_as_dir
NS_DECL(int, hid_serv_responsible_for_desc_id, (const char *id));

static int hid_serv_responsible_for_desc_id_response;

static int
NS(hid_serv_responsible_for_desc_id)(const char *id)
{
  return hid_serv_responsible_for_desc_id_response;
}


static void
test_rend_cache_clean_v2_descs_as_dir(void *data)
{
  rend_cache_entry_t *e;
  rend_service_descriptor_t *desc;

  (void)data;

  NS_MOCK(hid_serv_responsible_for_desc_id);
  rend_cache_init();

  // Test running with an empty cache
  rend_cache_clean_v2_descs_as_dir(time(NULL), 0);
  tt_int_op(digestmap_size(rend_cache_v2_dir), OP_EQ, 0);

  // Test with only one new entry
  e = tor_malloc_zero(sizeof(rend_cache_entry_t));
  e->last_served = time(NULL);
  desc = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  desc->timestamp = time(NULL);
  desc->pk = pk_generate(0);
  e->parsed = desc;
  digestmap_set(rend_cache_v2_dir, "abcde", e);

  hid_serv_responsible_for_desc_id_response = 1;
  rend_cache_clean_v2_descs_as_dir(time(NULL), 0);
  tt_int_op(digestmap_size(rend_cache_v2_dir), OP_EQ, 1);

 done:
  NS_UNMOCK(hid_serv_responsible_for_desc_id);
  rend_cache_purge();
}

#undef NS_SUBMODULE


struct testcase_t rend_cache_tests[] = {
  { "init", test_rend_cache_init, 0, NULL, NULL },
  { "decrement_allocation", test_rend_cache_decrement_allocation, 0, NULL, NULL },
  { "increment_allocation", test_rend_cache_increment_allocation, 0, NULL, NULL },
  { "clean", test_rend_cache_clean, 0, NULL, NULL },
  { "clean_v2_descs_as_dir", test_rend_cache_clean_v2_descs_as_dir, 0, NULL, NULL },
  { "free_all", test_rend_cache_free_all, 0, NULL, NULL },
  { "purge", test_rend_cache_purge, 0, NULL, NULL },
  { "failure_clean", test_rend_cache_failure_clean, 0, NULL, NULL },
  { "failure_entry_new", test_rend_cache_failure_entry_new, 0, NULL, NULL },
  { "failure_intro_add", test_rend_cache_failure_intro_add, 0, NULL, NULL },
  { "failure_intro_entry_new", test_rend_cache_failure_intro_entry_new, 0, NULL, NULL },
  { "failure_remove", test_rend_cache_failure_remove, 0, NULL, NULL },
  { "intro_failure_note", test_rend_cache_intro_failure_note, 0, NULL, NULL },
  { "lookup", test_rend_cache_lookup_entry, 0, NULL, NULL },
  { "lookup_v2_desc_as_dir", test_rend_cache_lookup_v2_desc_as_dir, 0, NULL, NULL },
  { "store_v2_desc_as_client", test_rend_cache_store_v2_desc_as_client, 0, NULL, NULL },
  { "store_v2_desc_as_client_with_different_time", test_rend_cache_store_v2_desc_as_client_with_different_time, 0, NULL, NULL },
  END_OF_TESTCASES
};
