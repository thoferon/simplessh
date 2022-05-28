#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <poll.h>

#include <libssh2.h>
#include <simplessh.h>

#define returnError(either, err) { \
  struct simplessh_either *tmp = (either); \
  tmp->side    = LEFT; \
  tmp->u.error = (err); \
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

int get_socket(const char *hostname, uint16_t port) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_NUMERICSERV;
  hints.ai_protocol = 0;

  struct addrinfo *res = NULL;
  char service[6]; // enough to contain a port number
  snprintf(service, 6, "%i", port);
  int rc = getaddrinfo(hostname, service, &hints, &res);
  if(rc != 0) {
    if(res) freeaddrinfo(res);
    return -1;
  }

  struct addrinfo *current;
  int sock;
  for(current = res; current != NULL; current = current->ai_next) {
    do {
      sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    } while(sock == -1 && errno == EINTR);
    if(sock == -1) continue;

    rc = connect(sock, res->ai_addr, res->ai_addrlen);

    if(rc == -1 && errno == EINTR) {
      do {
        struct pollfd pollfd;
        pollfd.fd     = sock;
        pollfd.events = POLLIN;

        rc = poll(&pollfd, 1, -1);
      } while(rc == -1 && errno == EINTR);

      if((rc & POLLIN) != POLLIN) rc = 0;
    }

    if(rc != -1) {
      freeaddrinfo(res);
      return sock;
    }

    close(sock);
  }

  freeaddrinfo(res);
  return -1;
}

struct simplessh_either *simplessh_open_session(
    const char *hostname,
    uint16_t port,
    const char *knownhosts_path) {
  struct simplessh_either *either;
  struct simplessh_session *session;
  LIBSSH2_KNOWNHOSTS *knownhosts;
  char *hostkey;
  int hostkey_type, rc;
  size_t hostkey_len;

  libssh2_init(0);

  #define returnLocalErrorSP(err) { \
    simplessh_close_session(session); \
    returnError(either, (err)); \
  }

  // Empty simplessh_session
  session = malloc(sizeof(struct simplessh_session));
  session->lsession = NULL;

  // Empty simplessh_either
  either = malloc(sizeof(struct simplessh_either));
  either->side    = RIGHT;
  either->u.value = session;

  // Connection initialisation
  session->sock = get_socket(hostname, port);
  if(session->sock == -1) returnError(either, CONNECT);

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
    either->side    = LEFT;
    either->u.error = AUTHENTICATION;
  } else {
    either->side    = RIGHT;
    either->u.value = session;
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
    either->side    = LEFT;
    either->u.error = AUTHENTICATION;
  } else {
    either->side    = RIGHT;
    either->u.value = session;
  }

  return either;
}

struct simplessh_either *simplessh_exec_command(
    struct simplessh_session *session,
    const char *command) {
  struct simplessh_either *either;
  struct simplessh_result *result;
  LIBSSH2_CHANNEL *channel;
  int rc, rc2;
  char *out = NULL;
  char *err = NULL;

  // Empty result
  result = malloc(sizeof(struct simplessh_result));
  result->out = NULL;
  result->err = NULL;
  result->exit_code   = 127;
  result->exit_signal = NULL;

  // Empty either
  either = malloc(sizeof(struct simplessh_either));
  either->side    = RIGHT;
  either->u.value = result;

  #define returnLocalErrorC(error) { \
    if(out != NULL) free(out); \
    if(err != NULL) free(err); \
    free(result); \
    returnError(either, (error)); \
  }

  while((channel = libssh2_channel_open_session(session->lsession)) == NULL) {
    if(libssh2_session_last_errno(session->lsession) == LIBSSH2_ERROR_EAGAIN)
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
  int out_size = 128, out_position = 0, err_size = 128, err_position = 0;
  out = malloc(out_size);
  err = malloc(err_size);

  for(;;) {
    rc  = libssh2_channel_read(channel,
                               out + out_position,
                               out_size - out_position - 1);
    rc2 = libssh2_channel_read_stderr(channel,
                                      err + err_position,
                                      err_size - err_position - 1);

    if(rc == 0 && rc2 == 0) {
      break;
    } else if(rc == LIBSSH2_ERROR_EAGAIN && rc2 == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else if((rc < 0  && rc  != LIBSSH2_ERROR_EAGAIN) ||
              (rc2 < 0 && rc2 != LIBSSH2_ERROR_EAGAIN)) {
      returnLocalErrorC(READ);
    } else {
      if(rc > 0) {
        out_position += rc;
        if(out_size - out_position < 1024) {
          out_size = min(out_size * 2, out_size + 65536);
          out = realloc(out, out_size);
        }
      }
      if(rc2 > 0) {
        err_position += rc2;
        if(err_size - err_position < 1024) {
          err_size = min(err_size * 2, err_size + 65536);
          err = realloc(err, err_size);
        }
      }
    }
  }
  out[out_position] = '\0';
  out = realloc(out, out_position + 1);
  result->out = out;

  err[err_position] = '\0';
  err = realloc(err, err_position + 1);
  result->err = err;

  while((rc = libssh2_channel_close(channel)) == LIBSSH2_ERROR_EAGAIN)
    waitsocket(session->sock, session->lsession);

  if(rc == 0) {
    result->exit_code = libssh2_channel_get_exit_status(channel);
    libssh2_channel_get_exit_signal(channel,
                                    &result->exit_signal, NULL,
                                    NULL, NULL,
                                    NULL, NULL);
  }


  libssh2_channel_free(channel);

  return either;
}

struct simplessh_either *simplessh_send_file(
    struct simplessh_session *session,
    int mode,
    const char *local_path,
    const char *destination_path) {
  struct simplessh_either *either;
  LIBSSH2_CHANNEL *channel = NULL;
  int rc;
  int *transferred = malloc(sizeof(int));
  *transferred = 0;

  // Empty either
  either = malloc(sizeof(struct simplessh_either));
  either->side    = RIGHT;
  either->u.value = transferred;

  #define returnLocalErrorS(err) { \
    if(f) fclose(f); \
    if(channel) libssh2_channel_free(channel); \
    either->side    = LEFT; \
    either->u.error = err; \
    return either; \
  }

  FILE *f = fopen(local_path, "r");
  if(f == NULL) returnLocalErrorS(FILEOPEN);

  size_t size;
  struct stat *fileinfo = malloc(sizeof(struct stat));
  stat(local_path, fileinfo);
  size = fileinfo->st_size;
  free(fileinfo);

  while((channel = libssh2_scp_send(session->lsession, destination_path, mode & 0777, size)) == NULL) {
    if(libssh2_session_last_errno(session->lsession) == LIBSSH2_ERROR_EAGAIN) {
      waitsocket(session->sock, session->lsession);
    } else {
      returnLocalErrorS(CHANNEL_OPEN);
    }
  }

  char buf[1024];
  char *current;
  while(!feof(f)) {
    size_t n = fread(buf, 1, sizeof(buf), f);
    current = buf;
    // Ready to write n bytes to the channel
    while(n > 0) {
      while((rc = libssh2_channel_write(channel, current, n)) == LIBSSH2_ERROR_EAGAIN);
      if(rc < 0) returnLocalErrorS(WRITE);
      n -= rc;
      current += rc;
      *transferred += rc;
    }
  }

  while(libssh2_channel_send_eof(channel) == LIBSSH2_ERROR_EAGAIN);
  while(libssh2_channel_close(channel) == LIBSSH2_ERROR_EAGAIN);
  while(libssh2_channel_free(channel) == LIBSSH2_ERROR_EAGAIN);
  fclose(f);
  return either;
}

void simplessh_close_session(struct simplessh_session *session) {
  libssh2_session_disconnect(session->lsession, "simplessh_close_session");
  libssh2_session_free(session->lsession);
  close(session->sock);
  free(session);
  libssh2_exit();
}
