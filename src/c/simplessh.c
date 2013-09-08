#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libssh2.h>
#include <simplessh.h>

#define returnError(either, err) { \
  struct simplessh_either *tmp = (either); \
  tmp->side  = LEFT; \
  tmp->error = (err); \
  return tmp; \
}

inline int min(int a, int b) {
  return a < b ? a : b;
}

static int waitsocket(int socket_fd, LIBSSH2_SESSION *session) {
  struct timeval timeout;
  int rc;
  fd_set fd;
  fd_set *writefd = NULL;
  fd_set *readfd = NULL;
  int dir;

  timeout.tv_sec = 10;
  timeout.tv_usec = 0;

  FD_ZERO(&fd);
  FD_SET(socket_fd, &fd);

  /* now make sure we wait in the correct direction */
  dir = libssh2_session_block_directions(session);

  if(dir & LIBSSH2_SESSION_BLOCK_INBOUND) readfd = &fd;
  if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) writefd = &fd;

  rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);
  return rc;
}

struct simplessh_either *simplessh_open_session(
    const char *hostname,
    uint16_t port,
    const char *knownhosts_path) {
  struct sockaddr_in sin;
  struct simplessh_either *either;
  struct simplessh_session *session;
  LIBSSH2_KNOWNHOSTS *knownhosts;
  char *hostkey;
  int hostkey_type, rc;
  size_t hostkey_len;

  #define returnLocalErrorSP(err) { \
    simplessh_close_session(session); \
    returnError(either, (err)); \
  }

  // Empty simplessh_session
  session = malloc(sizeof(struct simplessh_session));
  session->lsession = NULL;

  // Empty simplessh_either
  either = malloc(sizeof(struct simplessh_either));
  either->side  = RIGHT;
  either->value = session;

  // Connection initialisation
  session->sock = socket(AF_INET, SOCK_STREAM, 0);

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = inet_addr(hostname);

  rc = connect(session->sock, (const struct sockaddr*)&sin, sizeof(struct sockaddr_in));
  if(rc != 0) returnError(either, CONNECT);
  // End of connection initialisation

  session->lsession = libssh2_session_init();
  if(!session) returnLocalErrorSP(INIT);

  libssh2_session_set_blocking(session->lsession, 0);

  while((rc = libssh2_session_handshake(session->lsession, session->sock)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) returnLocalErrorSP(HANDSHAKE);

  // Check host in the knownhosts
  knownhosts = libssh2_knownhost_init(session->lsession);
  if(!knownhosts) returnLocalErrorSP(KNOWNHOSTS_INIT);

  libssh2_knownhost_readfile(knownhosts, knownhosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);

  hostkey = (char*)libssh2_session_hostkey(session->lsession, &hostkey_len, &hostkey_type);
  if(hostkey) {
    struct libssh2_knownhost *host;
    int check = libssh2_knownhost_check(knownhosts, hostname, hostkey, hostkey_len,
                                        LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                        &host);

    if(check != 0) returnLocalErrorSP(KNOWNHOSTS_CHECK);
    libssh2_knownhost_free(knownhosts);
  } else {
    libssh2_knownhost_free(knownhosts);
    returnLocalErrorSP(KNOWNHOSTS_HOSTKEY);
  }
  // End of the knownhosts checking

  return either;
}

struct simplessh_either *simplessh_authenticate_password(
    struct simplessh_session *session,
    const char *username,
    const char *password) {
  int rc;
  struct simplessh_either *either = malloc(sizeof(struct simplessh_either));

  while((rc = libssh2_userauth_password(session->lsession, username, password)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) {
    either->side  = LEFT;
    either->error = AUTHENTICATION;
  } else {
    either->side  = RIGHT;
    either->value = session;
  }

  return either;
}

struct simplessh_either *simplessh_authenticate_key(
    struct simplessh_session *session,
    const char *username,
    const char *public_key_path,
    const char *private_key_path,
    const char *passphrase) {
  int rc;
  struct simplessh_either *either = malloc(sizeof(struct simplessh_either));

  while((rc = libssh2_userauth_publickey_fromfile(session->lsession, username, public_key_path, private_key_path, passphrase)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) {
    either->side  = LEFT;
    either->error = AUTHENTICATION;
  } else {
    either->side  = RIGHT;
    either->value = session;
  }

  return either;
}

struct simplessh_either *simplessh_exec_command(
    struct simplessh_session *session,
    const char *command) {
  struct simplessh_either *either;
  struct simplessh_result *result;
  LIBSSH2_CHANNEL *channel;
  int rc;

  // Empty result
  result = malloc(sizeof(struct simplessh_result));
  result->exit_code = 127;

  // Empty either
  either = malloc(sizeof(struct simplessh_either));
  either->side = RIGHT;
  either->value = result;

  #define returnLocalErrorC(err) { returnError(either, (err)); }

  while((channel = libssh2_channel_open_session(session->lsession)) == NULL) {
    if(libssh2_session_last_error(session->lsession, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
      waitsocket(session->sock, session->lsession);
    else
      returnLocalErrorC(CHANNEL_OPEN);
  }

  // Send the command
  while((rc = libssh2_channel_exec(channel, command)) != 0) {
    if(rc == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else {
      returnLocalErrorC(CHANNEL_EXEC);
    }
  }

  // Read result
  int content_size = 128, content_position = 0;
  char *content = malloc(content_size);

  for(;;) {
    rc = libssh2_channel_read(channel,
        content + content_position,
        content_size - content_position - 1); // Don't forget the \0

    if(rc < 0) {
      if(rc == LIBSSH2_ERROR_EAGAIN)
        waitsocket(session->sock, session->lsession);
      else
        returnLocalErrorC(READ);
    } else if(rc > 0) {
      content_position += rc;
      if(content_size - content_position > 1024) {
        content_size = min(content_size * 2, content_size + 1024);
        content = realloc(content, content_size);
      }
    } else {
      break;
    }
  }
  content[content_position] = '\0';
  result->content = content;

  while((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
    waitsocket(session->sock, session->lsession);

  if(rc == 0)
    result->exit_code = libssh2_channel_get_exit_status(channel);
    // TODO: signal ?

  libssh2_channel_free(channel);

  return either;
}

void simplessh_close_session(struct simplessh_session *session) {
  libssh2_session_disconnect(session->lsession, "simplessh_close_session");
  libssh2_session_free(session->lsession);
  close(session->sock);
  free(session);
  libssh2_exit();
}

