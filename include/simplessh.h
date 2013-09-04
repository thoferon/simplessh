#ifdef __simplessh_header
#else
#define __simplessh_header

#include <libssh2.h>

enum simplessh_either {
  LEFT,
  RIGHT
};

enum simplessh_error {
  NOERROR,
  CONNECT,
  INIT,
  HANDSHAKE,
  KNOWNHOSTS_INIT,
  KNOWNHOSTS_HOSTKEY,
  KNOWNHOSTS_CHECK,
  AUTHENTICATION,
  CHANNEL_OPEN,
  CHANNEL_EXEC,
  READ
};

struct simplessh_result {
  enum simplessh_either type;
  enum simplessh_error error;
  char *content;
};

struct simplessh_session {
  enum simplessh_either type;
  enum simplessh_error error;
  LIBSSH2_SESSION *lsession;
  int sock;
};

struct simplessh_session *simplessh_open_session_password(
  const char*,
  uint16_t,
  const char*,
  const char*,
  const char*);

struct simplessh_result *simplessh_exec_command(
  struct simplessh_session*,
  const char *);

int simplessh_free_result(struct simplessh_result*);

int simplessh_close_session(struct simplessh_session*);

#endif

