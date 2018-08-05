#include "shared.h"
#include <assert.h>

int main(void) {
  shared_func();

  assert(data==1);

  return 0;
}

