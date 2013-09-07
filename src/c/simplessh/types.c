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

