#ifndef __SIMPLESSH_TYPES_HEADER
#define __SIMPLESSH_TYPES_HEADER

#include <libssh2.h>

enum simplessh_left_right {
  LEFT,
  RIGHT
};

enum simplessh_error {
  CONNECT            = 1,
  INIT               = 2,
  HANDSHAKE          = 3,
  KNOWNHOSTS_INIT    = 4,
  KNOWNHOSTS_HOSTKEY = 5,
  KNOWNHOSTS_CHECK   = 6,
  AUTHENTICATION     = 7,
  CHANNEL_OPEN       = 8,
  CHANNEL_EXEC       = 9,
  READ               = 10
};

struct simplessh_either {
  enum simplessh_left_right side;
  enum simplessh_error error;
  void *value;
};

struct simplessh_session {
  LIBSSH2_SESSION *lsession;
  int sock;
};

int simplessh_is_left(struct simplessh_either*);
int simplessh_get_error(struct simplessh_either*);
void *simplessh_get_value(struct simplessh_either*);

#endif

