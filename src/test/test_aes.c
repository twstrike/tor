/* Copyright (c) 2010-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"

#include "test.h"

#define AES_PRIVATE
#include "aes.h"

#define NS_MODULE aes


static void
test_aes_cipher_free(void *ignored)
{
  (void)ignored;

  aes_cipher_free(NULL);
}


struct testcase_t aes_tests[] = {
  { "cipher_free", test_aes_cipher_free, 0, NULL, NULL },
  END_OF_TESTCASES
};
