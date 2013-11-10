#ifndef __SIMPLESSH_TYPES_HEADER
#define __SIMPLESSH_TYPES_HEADER 1

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
  READ               = 10,
  FILEOPEN           = 11,
  WRITE              = 12
};

struct simplessh_either {
  enum simplessh_left_right side;
  union {
    enum simplessh_error error;
    void *value;
  } u;
};

struct simplessh_session {
  LIBSSH2_SESSION *lsession;
  int sock;
};

struct simplessh_result {
  char *out;
  char *err;
  int exit_code;
  char *exit_signal;
};

int simplessh_is_left(struct simplessh_either*);
int simplessh_get_error(struct simplessh_either*);
void *simplessh_get_value(struct simplessh_either*);

void simplessh_free_either_result(struct simplessh_either*);
void simplessh_free_either_count(struct simplessh_either*);

char *simplessh_get_out(struct simplessh_result*);
char *simplessh_get_err(struct simplessh_result*);
int simplessh_get_exit_code(struct simplessh_result*);
char *simplessh_get_exit_signal(struct simplessh_result*);

int simplessh_get_count(int*);

#endif
