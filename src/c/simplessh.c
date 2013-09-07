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

struct simplessh_either *simplessh_open_session_password(
    const char *hostname,
    uint16_t port,
    const char *username,
    const char *password,
    const char *knownhosts_path) {
  struct sockaddr_in sin;
  struct simplessh_either *either;
  struct simplessh_session *session;
  LIBSSH2_KNOWNHOSTS *knownhosts;
  char *hostkey;
  int hostkey_type, rc;
  size_t hostkey_len;

  #define returnLocalError(err) { \
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
  if(!session) returnLocalError(INIT);

  libssh2_session_set_blocking(session->lsession, 0);

  while(rc = (libssh2_session_handshake(session->lsession, session->sock)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) returnLocalError(HANDSHAKE);

  // Check host in the knownhosts
  knownhosts = libssh2_knownhost_init(session->lsession);
  if(!knownhosts) returnLocalError(KNOWNHOSTS_INIT);

  libssh2_knownhost_readfile(knownhosts, knownhosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);

  hostkey = (char*)libssh2_session_hostkey(session->lsession, &hostkey_len, &hostkey_type);
  if(hostkey) {
    struct libssh2_knownhost *host;
    int check = libssh2_knownhost_check(knownhosts, hostname, hostkey, hostkey_len,
                                        LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                        &host);

    if(check != 0) returnLocalError(KNOWNHOSTS_CHECK);
    libssh2_knownhost_free(knownhosts);
  } else {
    libssh2_knownhost_free(knownhosts);
    returnLocalError(KNOWNHOSTS_HOSTKEY);
  }
  // End of the knownhosts checking

  // Authentication
  while((rc = libssh2_userauth_password(session->lsession, username, password)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) returnLocalError(AUTHENTICATION);

  return either;
}

struct simplessh_either *simplessh_exec_command(
    struct simplessh_session *session,
    const char *command) {
  struct simplessh_either *either;
  LIBSSH2_CHANNEL *channel;
  int rc;

  #define returnLocalError(err) { returnError(either, (err)); }

  while((channel = libssh2_channel_open_session(session->lsession)) == NULL) {
    if(libssh2_session_last_error(session->lsession, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN)
      waitsocket(session->sock, session->lsession);
    else
      returnError(either, CHANNEL_OPEN);
  }

  // Empty either
  either = malloc(sizeof(struct simplessh_either));
  either->side = RIGHT;

  // Send the command
  while((rc = libssh2_channel_exec(channel, command)) != 0) {
    if(rc == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else {
      returnLocalError(CHANNEL_EXEC);
    }
  }

  // Read result
  int content_size = 1024, content_position = 0;
  char *content = malloc(content_size);
  #define returnLocalError(err) { free(content); returnError(either, (err)); }

  for(;;) {
    rc = libssh2_channel_read(channel,
        content + content_position,
        content_size - content_position - 1); // Don't forget the \0

    if(rc < 0) {
      if(rc == LIBSSH2_ERROR_EAGAIN)
        waitsocket(session->sock, session->lsession);
      else
        returnLocalError(READ);
    } else if(rc > 0) {
      content_position += rc;
      content_size += 1024;
      content = realloc(content, content_size);
    } else {
      break;
    }
  }
  content[content_position] = '\0';

  // TODO: channel close/free, deal with exit status, signals

  either->value = content;
  return either;
}

int simplessh_close_session(struct simplessh_session *session) {
  close(session->sock);
  libssh2_session_disconnect(session->lsession, "simplessh_close_session");
  libssh2_session_free(session->lsession);
  free(session);
  libssh2_exit();
}

