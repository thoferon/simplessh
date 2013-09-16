#ifndef __simplessh_header
#define __simplessh_header 1

#include <stdint.h>

#include <simplessh/types.h>

struct simplessh_either *simplessh_open_session(
  const char*,
  uint16_t,
  const char*);

struct simplessh_either *simplessh_authenticate_password(
  struct simplessh_session*,
  const char *username,
  const char *password);

struct simplessh_either *simplessh_authenticate_key(
  struct simplessh_session*,
  const char*,
  const char*,
  const char*,
  const char*);

struct simplessh_either *simplessh_exec_command(
  struct simplessh_session*,
  const char *);

struct simplessh_either *simplessh_send_file(
  struct simplessh_session*,
  int,
  const char*,
  const char*);

void simplessh_close_session(struct simplessh_session*);

#endif

