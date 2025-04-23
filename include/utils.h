#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

#define SANDBOX_LOG(...) fprintf(stdout, "[+] " __VA_ARGS__)
#define SANDBOX_ERR(fmt, ...)                                                  \
  fprintf(stdout, "[+] %s:%d: " fmt, __FILE__, __LINE__ __VA_ARGS__)

#endif /* UTILS_H */
