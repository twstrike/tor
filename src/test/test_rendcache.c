/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "config.h"
#include "dirvote.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "routerlist.h"
#include "routerparse.h"
#include "torcert.h"

#include "test.h"
#include "rendcache.h"

static const char *hs_desc_content = "rendezvous-service-descriptor 3xqunszqnaolrrfmtzgaki7mxelgvkje\n\
version 2\n\
permanent-key\n\
-----BEGIN RSA PUBLIC KEY-----\n\
MIGJAoGBAKUr5opfKa29Q1lBK78k2+Crqliaolam/8/MDMTJ7OXt8XRAgSHzgp3A\n\
ZDpxdiDZPcHOQat+4b1Kx9H8sutVX9fjDZXEf/Iaj5E9aCt8AEC/HusS3qlkPNi0\n\
Y1AnxDR8j1cD6rU2OODnPLLQ7Q2KufE6Zfz9UW/yjZELRhykfbwjAgMBAAE=\n\
-----END RSA PUBLIC KEY-----\n\
secret-id-part os4hldf7a6v4r55yji2hv5yijuok57v6\n\
publication-time 2015-08-18 16:52:18\n\
protocol-versions 1,3,5\n\
introduction-points\n\
-----BEGIN MESSAGE-----\n\
aW50cm9kdWN0aW9uLXBvaW50IHlkbzd2MmU0ZGx3Zng0YzN2Mm9jaXpmNWZoM2dk\n\
N2x0CmlwLWFkZHJlc3MgMC4wLjg3Ljk0Cm9uaW9uLXBvcnQgMTIxMjgKb25pb24t\n\
a2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0tLQpNSUdKQW9HQkFLMHBN\n\
VjFXY3dMR1l4VFEzeTRpQUx3anJ3SE9NdFV0ZVZ0R0puaDFyR3pZb1BTSEZzQmY4\n\
YXZUCkJ3SFFlSFZ1V3pUSmxIcVFrbTRZUVFjbm5FNVdtQVU4ckx6OEpEQ0F5M2dx\n\
RjZiV2l3WFM3RElHaVRNZ2s2RzQKSUlqUFFtQlpxNUJJaUkwZHp6MWFjVGpvQkRP\n\
T1Rnb3dRRFAwSHRYZFhvWExaN0JyRElEN0FnTUJBQUU9Ci0tLS0tRU5EIFJTQSBQ\n\
VUJMSUMgS0VZLS0tLS0Kc2VydmljZS1rZXkKLS0tLS1CRUdJTiBSU0EgUFVCTElD\n\
IEtFWS0tLS0tCk1JR0pBb0dCQUwzQkVBbGl4ajZEemxuM2N1alVtOXdxUGpMOUhx\n\
UXpKSGVBMjltbFg0VFJmWnAvMWxza29Bc3gKY3NtUkIwYnM3NFM0RkNhaWxqV3Z3\n\
QXlnb3RUUlpNUTZvSVZvOGN0ZXhaRVY4SWw0QVM1Vk5aMjMzeXl1N3dMdwpCNmlh\n\
aWdrTFBRNjQwbFhxV1ZQL2huN0k2TXRuWGtyYytJbVFGQVdPWGdxK3RFTVRaYThu\n\
QWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQppbnRyb2R1Y3Rp\n\
b24tcG9pbnQgaGVneG8ybXlnaDZhNTJic3V1bGE0cnN1Y3J3NWwyYzcKaXAtYWRk\n\
cmVzcyAwLjAuMjQ4LjE4NApvbmlvbi1wb3J0IDQ0NzYxCm9uaW9uLWtleQotLS0t\n\
LUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFvR0JBT2RBbnBPemV5Tm5v\n\
MVNBNWlBTG9MSUE2ZnpBQnZFR1RkSkxDMUVpNndRYzkrKzJqWUJvS0UrbAphZTJ6\n\
Q05IOER3VFQrTTNjZ0dWRy9oNjd3Y2taMjc5a2ovOXBBWnQxN2Ric0hoSVFtNE1B\n\
VHE1OTJhbm0rVGFrCmRhMmI0ck1Pcmp4d2RDUlRYMzNWYmxST2kxSzJBRk1XUmg1\n\
MVYwWHhmcVZrWS9ZVVZqeTlBZ01CQUFFPQotLS0tLUVORCBSU0EgUFVCTElDIEtF\n\
WS0tLS0tCnNlcnZpY2Uta2V5Ci0tLS0tQkVHSU4gUlNBIFBVQkxJQyBLRVktLS0t\n\
LQpNSUdKQW9HQkFMM0JFQWxpeGo2RHpsbjNjdWpVbTl3cVBqTDlIcVF6SkhlQTI5\n\
bWxYNFRSZlpwLzFsc2tvQXN4CmNzbVJCMGJzNzRTNEZDYWlsald2d0F5Z290VFJa\n\
TVE2b0lWbzhjdGV4WkVWOElsNEFTNVZOWjIzM3l5dTd3THcKQjZpYWlna0xQUTY0\n\
MGxYcVdWUC9objdJNk10blhrcmMrSW1RRkFXT1hncSt0RU1UWmE4bkFnTUJBQUU9\n\
Ci0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0KaW50cm9kdWN0aW9uLXBvaW50\n\
IGF6M2dsNmtwdTJ4d25lM2t6MjM1dzdmZXFvYjY2ZGt1CmlwLWFkZHJlc3MgMC4w\n\
LjEyOS4xMzIKb25pb24tcG9ydCA0MjMzNwpvbmlvbi1rZXkKLS0tLS1CRUdJTiBS\n\
U0EgUFVCTElDIEtFWS0tLS0tCk1JR0pBb0dCQUs1Ym4xNWpuS3pvU3k4aDJKZWpQ\n\
WGVDdis3WkhnMGNocHowUStkUk5TTFMraXptaUoraEhSeGoKR2VRbEEvUCswR3ZJ\n\
QjQxS01ocnVJQ243clRKVzk0dDJxR1hCVTBYVTlMTHUyR0FNTHpLQ0hwTG0rdm9h\n\
WWkvegorR0NHamt6K3h3a1hUZVF0enVHN2dFemJrVDZxZEIyRzBITkZVOEhldlJ2\n\
MTY0L1VERTBoQWdNQkFBRT0KLS0tLS1FTkQgUlNBIFBVQkxJQyBLRVktLS0tLQpz\n\
ZXJ2aWNlLWtleQotLS0tLUJFR0lOIFJTQSBQVUJMSUMgS0VZLS0tLS0KTUlHSkFv\n\
R0JBTDNCRUFsaXhqNkR6bG4zY3VqVW05d3FQakw5SHFRekpIZUEyOW1sWDRUUmZa\n\
cC8xbHNrb0FzeApjc21SQjBiczc0UzRGQ2FpbGpXdndBeWdvdFRSWk1RNm9JVm84\n\
Y3RleFpFVjhJbDRBUzVWTloyMzN5eXU3d0x3CkI2aWFpZ2tMUFE2NDBsWHFXVlAv\n\
aG43STZNdG5Ya3JjK0ltUUZBV09YZ3ErdEVNVFphOG5BZ01CQUFFPQotLS0tLUVO\n\
RCBSU0EgUFVCTElDIEtFWS0tLS0tCgo=\n\
-----END MESSAGE-----\n\
signature\n\
-----BEGIN SIGNATURE-----\n\
JiOLtXzEgN43Ai5wdF8YawjuzAV5dpBCDA4RfUWoOuVkWUPA5L24SHtN5bnbIQE0\n\
LnGCMU4+SjG9hN9fbO2gHzBzzNklNLX6E+vrkTCCYnul/QAeB1Vqdnk2Ml3bSZX0\n\
d8UCllh0LkFlTBssEe4hQ96PXeZui6H7BGrBDgrLAq0=\n\
-----END SIGNATURE-----";

static rend_data_t
mock_rend_data(void)
{
  rend_data_t rend_query;

  memset(&rend_query, 0, sizeof(rend_query));
  strncpy(rend_query.onion_address, "p5ilyyatkmqeoat2", REND_SERVICE_ID_LEN_BASE32+1);
  rend_query.auth_type = REND_NO_AUTH;
  rend_query.hsdirs_fp = smartlist_new();
  smartlist_add(rend_query.hsdirs_fp, tor_memdup("aaaaaaaaaaaaaaaaaaaaaaaa", DIGEST_LEN));

  return rend_query;
}

static void
test_rend_cache_lookup_entry(void *data)
{
  int ret;
  rend_data_t mock_rend_query;
  char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];

  (void)data;

  rend_cache_init();

  ret = rend_cache_lookup_entry("invalid query", 2, NULL);
  tt_int_op(ret, OP_EQ, -EINVAL);

  ret = rend_cache_lookup_entry("abababababababab", 2, NULL);
  tt_int_op(ret, OP_EQ, -ENOENT);

  ret = rend_cache_lookup_entry("abababababababab", 4224, NULL);
  tt_int_op(ret, OP_EQ, -ENOENT);

  mock_rend_query = mock_rend_data();
  base32_encode(desc_id_base32, sizeof(desc_id_base32), "3xqunszqnaolrrfmtzgaki7mxelgvkje", DIGEST_LEN);
  rend_cache_store_v2_desc_as_client(hs_desc_content, "3xqunszqnaolrrfmtzgaki7mxelgvkje", &mock_rend_query, NULL);

  ret = rend_cache_lookup_entry("p5ilyyatkmqeoat2", 2, NULL);
  tt_int_op(ret, OP_EQ, 0);

 done:
  (void)1;
}

struct testcase_t rendcache_tests[] = {
  { "cache_lookup", test_rend_cache_lookup_entry, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
