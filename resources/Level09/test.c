#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char* test(char* s) {
  int i = -1;
  char* newstr;
  newstr = malloc(sizeof(char) * strlen(s));
  while (s[++i])
    newstr[i] = s[i] - i;
  return newstr;
}

int main(int ac, char **av) {
  if (ac != 2)
    exit(1);
  char* res = test(av[1]);
  printf("%s", res);
  free(res);
  return 0;
}
