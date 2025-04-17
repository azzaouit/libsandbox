#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "ping.h"
#include "scmp.h"

#define STACK_SIZE (1024 * 1024)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Minimal allowlist for an icmp echo
static struct scmp_rule ping_rules[] = {
    {"socket", SCMP_ACT_ALLOW, {}}, {"sendto", SCMP_ACT_ALLOW, {}},
    {"write", SCMP_ACT_ALLOW, {}},  {"close", SCMP_ACT_ALLOW, {}},
    {"dup", SCMP_ACT_ALLOW, {}},    {"fcntl", SCMP_ACT_ALLOW, {}},
    {"fstat", SCMP_ACT_ALLOW, {}},  {"exit_group", SCMP_ACT_ALLOW, {}},
    {"getpid", SCMP_ACT_ALLOW, {}}, {"exit", SCMP_ACT_ALLOW, {}},
};

int sandboxed_ping() {
  char dest_ip[] = "8.8.8.8";
  printf("Child PID: %d\n", getpid());
  scmp_setup_signal_handler();
  assert(!scmp_apply_rules(ping_rules, ARRAY_SIZE(ping_rules)));
  assert(!ping(dest_ip));
  return 0;
}

int main() {
  char *stack = malloc(STACK_SIZE);
  pid_t child_pid = clone(sandboxed_ping, stack + STACK_SIZE, SIGCHLD, NULL);
  assert(child_pid != -1);
  printf("Parent PID: %d\n", getpid());
  waitpid(child_pid, NULL, 0);
  free(stack);
  return 0;
}
