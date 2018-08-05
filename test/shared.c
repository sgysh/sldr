#include "shared.h"
#include <stdio.h>

int data = 1;

void shared_func(void) {
  printf("%s\n", __func__);
}
