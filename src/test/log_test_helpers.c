#include "log_test_helpers.h"

static mock_saved_log_entry_t *saved_logs = NULL;

void
mock_clean_saved_logs(void)
{
  mock_saved_log_entry_t *tmp;
  mock_saved_log_entry_t *local_saved_logs = saved_logs;
  saved_logs = NULL;
  while(local_saved_logs) {
    tmp = local_saved_logs->next;
    tor_free(local_saved_logs);
    local_saved_logs = tmp;
  }
}

const mock_saved_log_entry_t *
mock_saved_logs(void)
{
  return saved_logs;
}

void
mock_saving_logv(int severity, log_domain_mask_t domain, const char *funcname, const char *suffix, const char *format, va_list ap)
{
  char buf[10240];
  int n;
  n = tor_vsnprintf(buf,sizeof(buf),format,ap);
  buf[n]='\n';
  buf[n+1]='\0';

  mock_saved_log_entry_t *e = tor_malloc_zero(sizeof(mock_saved_log_entry_t));
  e->severity = severity;
  e->funcname = funcname;
  e->suffix = suffix;
  e->format = format;
  e->generated_msg = buf;
  e->next = saved_logs;
  saved_logs = e;
}
