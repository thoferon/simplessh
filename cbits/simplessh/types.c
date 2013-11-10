#include <stdlib.h>
#include <stdio.h>

#include <simplessh/types.h>

int simplessh_is_left(struct simplessh_either *either) {
  return either->side == LEFT;
}

int simplessh_get_error(struct simplessh_either *either) {
  if(either->side != LEFT) {
    fprintf(stderr, "Error: simplessh_get_error: trying to get the error of a Right element\n");
    abort();
  }
  return either->u.error;
}

void *simplessh_get_value(struct simplessh_either *either) {
  if(either->side != RIGHT) {
    fprintf(stderr, "Error: simplessh_get_value: trying to get the value of a Left element\n");
    abort();
  } else if(either->u.value == NULL) {
    fprintf(stderr, "Error: simplessh_get_value: element is Right but value has not been set\n");
    abort();
  }
  return either->u.value;
}

void simplessh_free_either_result(struct simplessh_either *either) {
  struct simplessh_result *result = either->u.value;
  if(either->side == RIGHT && result != NULL) {
    if(result->out != NULL) free(result->out);
    if(result->err != NULL) free(result->err);
    if(result->exit_signal != NULL) free(result->exit_signal);
    free(result);
  }
  free(either);
}

void simplessh_free_either_count(struct simplessh_either *either) {
  if(either->side == RIGHT && either->u.value != NULL) free(either->u.value);
  free(either);
}

char *simplessh_get_out(struct simplessh_result *result) {
  return result->out;
}

char *simplessh_get_err(struct simplessh_result *result) {
  return result->err;
}

int simplessh_get_exit_code(struct simplessh_result *result) {
  return result->exit_code;
}

char *simplessh_get_exit_signal(struct simplessh_result *result) {
  return result->exit_signal;
}

int simplessh_get_count(int *ptr) {
  return *ptr;
}
