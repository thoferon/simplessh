#ifndef __simplessh_header
#define __simplessh_header

#include <simplessh/types.h>

struct simplessh_either *simplessh_open_session_password(
  const char*,
  uint16_t,
  const char*,
  const char*,
  const char*);

struct simplessh_either *simplessh_exec_command(
  struct simplessh_session*,
  const char *);

void simplessh_close_session(struct simplessh_session*);

#endif

