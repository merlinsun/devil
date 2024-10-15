#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
  int *p = (int *)malloc(sizeof(int)*4);
  memset(p, 0, sizeof(p));
  printf("%d %d", p[0], p[3]);
  free(p);
  return 0;
}