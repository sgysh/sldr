#include <stdio.h>
#include <stdlib.h>

#define PRINT_FUNC() do {printf("%s\n", __func__);} while(0)

__attribute__((constructor)) static void ctor() {
  PRINT_FUNC();
}

__attribute__((constructor)) static void ctor2() {
  PRINT_FUNC();
}

static void dtor() {
  PRINT_FUNC();
}

int main(void) {
  PRINT_FUNC();
  atexit(dtor);

  return 0;
}
