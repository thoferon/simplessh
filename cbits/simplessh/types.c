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
  return either->error;
}

void *simplessh_get_value(struct simplessh_either *either) {
  if(either->side != RIGHT) {
    fprintf(stderr, "Error: simplessh_get_value: trying to get the value of a Left element\n");
    abort();
  } else if(either->value == NULL) {
    fprintf(stderr, "Error: simplessh_get_value: element is Right but value has not been set\n");
    abort();
  }
  return either->value;
}

void simplessh_free_either_result(struct simplessh_either *either) {
  struct simplessh_result *result = either->value;
  if(result != NULL) {
    if(result->content != NULL) free(result->content);
    free(result);
  }
  free(either);
}

void simplessh_free_either_count(struct simplessh_either *either) {
  if(either->value != NULL) free(either->value);
  free(either);
}

char *simplessh_get_content(struct simplessh_result *result) {
  return result->content;
}

int simplessh_get_exit_code(struct simplessh_result *result) {
  return result->exit_code;
}

int simplessh_get_count(int *ptr) {
  return *ptr;
}

