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

struct simplessh_session *simplessh_open_session_password(
    const char *hostname,
    uint16_t port,
    const char *username,
    const char *password,
    const char *knownhosts_path) {
  int sock;
  struct sockaddr_in sin;
  struct simplessh_session *session;
  LIBSSH2_SESSION *lsession;
  LIBSSH2_KNOWNHOSTS *knownhosts;
  char *hostkey;
  int hostkey_type;
  size_t hostkey_len;

  // Empty simplessh_session
  session = (struct simplessh_session*)malloc(sizeof(struct simplessh_session));
  session->type = RIGHT;
  session->error = NOERROR;
  session->lsession = NULL;
  session->sock = 0;

  // Connection initialisation
  sock = socket(AF_INET, SOCK_STREAM, 0);

  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  sin.sin_addr.s_addr = inet_addr(hostname);

  if(connect(sock, (const struct sockaddr*)&sin, sizeof(struct sockaddr_in)) != 0)
    return mkErrorSession((struct simplessh_session*)&session, CONNECT);
  // End of connection initialisation

  lsession = libssh2_session_init();
  if(!session) return mkErrorSession((struct simplessh_session*)&session, INIT);

  libssh2_session_set_blocking(lsession, 1);

  if(libssh2_session_handshake(lsession, sock) != 0)
    return mkErrorSession((struct simplessh_session*)&session, HANDSHAKE);

  // Check host in the knownhosts
  knownhosts = libssh2_knownhost_init(lsession);
  if(!knownhosts) return mkErrorSession((struct simplessh_session*)&session, KNOWNHOSTS);

  libssh2_knownhost_readfile(knownhosts, knownhosts_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);

  hostkey = (char*)libssh2_session_hostkey(lsession, &hostkey_len, &hostkey_type);
  if(hostkey) {
    struct libssh2_knownhost *host;
    int check = libssh2_knownhost_check(knownhosts, hostname, hostkey, hostkey_len,
                                        LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW,
                                        &host);
    fprintf(stderr, "Host check: %d, key: %s\n", check,
                        (check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH)?
                                        host->key:"<none>");
  }
  libssh2_knownhost_free(knownhosts);

  // End of the knownhosts checking

  return session;
}

struct simplessh_result *simplessh_exec_command(
    struct simplessh_session *session,
    const char *command) {
  return NULL;
}

int simplessh_close_session(struct simplessh_session *session) {

}

