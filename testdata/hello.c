#include <stdio.h>

int             testValue   = 1;
const char      testString[] = "test";

int
main(void)
{
  printf("hello, world, testValue is: %d, testString: %s\n", testValue,
         testString);

  return 0;
}
