#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ping.h"
#include "sandbox.h"

#define STACK_SIZE (1024 * 1024)

// Sandboxed process
static int sandboxed_ping() {
  printf("My PID: %d\n", getpid());
  char dest_ip[] = "8.8.8.8";
  assert(!ping(dest_ip));
  return 0;
}

int main() {
  (void)ping_rules;
  struct sandbox s = {.uuid = {},
                      .stack_size = STACK_SIZE,
                      .c.cpu_max_quota = 100000,
                      .c.cpu_max_period = 100000,
                      .c.mem_max = 100000000,
                      .c.mem_swap_max = 0,
                      .r = ping_rules,
                      .nrules = ARRAY_SIZE(ping_rules),
                      .f_entry = sandboxed_ping};

  assert(!sandbox(&s));

  return 0;
}
