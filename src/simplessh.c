#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <libssh2.h>
#include <simplessh.h>

/* A helper function to mutate a simplessh_session to make it an error */
struct simplessh_session *mkErrorSession(
    struct simplessh_session *session,
    enum simplessh_error error) {
  session->type = LEFT;
  session->error = error;
  return session;
}

/* A helper function to mutate a simplessh_result to make it an error */
struct simplessh_result *mkErrorResult(
    struct simplessh_result *result,
    enum simplessh_error error) {
  result->type = LEFT;
  result->error = error;
  return result;
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

struct simplessh_session *simplessh_open_session_password(
    const char *hostname,
    uint16_t port,
    const char *username,
    const char *password,
    const char *knownhosts_path) {
  struct sockaddr_in sin;
  struct simplessh_session *session;
  LIBSSH2_KNOWNHOSTS *knownhosts;
  char *hostkey;
  int hostkey_type, rc;
  size_t hostkey_len;

  // Empty simplessh_session
  session = (struct simplessh_session*)malloc(sizeof(struct simplessh_session));
  session->type = RIGHT;
  session->error = NOERROR;
  session->lsession = NULL;

  // Connection initialisation
  session->sock = socket(AF_INET, SOCK_STREAM, 0);

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = inet_addr(hostname);

  if(connect(session->sock, (const struct sockaddr*)&sin, sizeof(struct sockaddr_in)) != 0)
    return mkErrorSession(session, CONNECT);
  // End of connection initialisation

  session->lsession = libssh2_session_init();
  if(!session) return mkErrorSession((struct simplessh_session*)&session, INIT);

  libssh2_session_set_blocking(session->lsession, 0);

  while(rc = (libssh2_session_handshake(session->lsession, session->sock)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) return mkErrorSession(session, HANDSHAKE);

  // Check host in the knownhosts
  knownhosts = libssh2_knownhost_init(session->lsession);
  if(!knownhosts) return mkErrorSession(session, KNOWNHOSTS_INIT);

  libssh2_knownhost_readfile(knownhosts, knownhosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);

  hostkey = (char*)libssh2_session_hostkey(session->lsession, &hostkey_len, &hostkey_type);
  if(hostkey) {
    struct libssh2_knownhost *host;
    int check = libssh2_knownhost_check(knownhosts, hostname, hostkey, hostkey_len,
                                        LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                        &host);

    fprintf(stderr, "Host check: %d, key: %s\n", check,
                        (check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
                                        host->key:"<none>");

    if(check != 0) return mkErrorSession(session, KNOWNHOSTS_CHECK);
    libssh2_knownhost_free(knownhosts);
  } else {
    libssh2_knownhost_free(knownhosts);
    return mkErrorSession(session, KNOWNHOSTS_HOSTKEY);
  }
  // End of the knownhosts checking

  // Authentication
  while((rc = libssh2_userauth_password(session->lsession, username, password)) == LIBSSH2_ERROR_EAGAIN);
  if(rc) return mkErrorSession(session, AUTHENTICATION);

  return session;
}

struct simplessh_result *simplessh_exec_command(
    struct simplessh_session *session,
    const char *command) {
  struct simplessh_result *result;
  LIBSSH2_CHANNEL *channel;
  int rc;

  while((channel = libssh2_channel_open_session(session->lsession)) == NULL) {
    if(libssh2_session_last_error(session->lsession, NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else {
      return mkErrorSession(session, CHANNEL_OPEN);
    }
  }

  // Empty result
  result = (struct simplessh_result*)malloc(sizeof(struct simplessh_result));
  result->type = RIGHT;
  result->error = NOERROR;

  // Send the command
  while((rc = libssh2_channel_exec(channel, command)) != 0) {
    if(rc == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else {
      return mkErrorResult(result, CHANNEL_EXEC);
    }
  }

  // Read result
  int content_size = 1024, content_position = 0;
  result->content = (char*)malloc(content_size);
  for(;;) {
    rc = libssh2_channel_read(channel,
        result->content + content_position,
        content_size - content_position - 1); // Don't forget the \0

    if(rc < 0) {
      if(rc == LIBSSH2_ERROR_EAGAIN)
        waitsocket(session->sock, session->lsession);
      else
        return mkErrorResult(result, READ);
    } else if(rc > 0) {
      content_position += rc;
      content_size += 1024;
      result->content = (char*)realloc(result->content, content_size);
    } else {
      break;
    }
  }
  result->content[content_position] = '\0';

  return result;
}

int simplessh_free_result(struct simplessh_result *result) {
  if(result->content != NULL) free(result->content);
  free(result);
}

int simplessh_close_session(struct simplessh_session *session) {
  close(session->sock);
  libssh2_session_disconnect(session->lsession, "simplessh_close_session");
  libssh2_session_free(session->lsession);
  free(session);
  libssh2_exit();
}

