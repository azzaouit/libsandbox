#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sandbox.h"

#define STACK_SIZE (1024 * 1024)

// Sandboxed process
int child_func() {
  printf("Child PID: %d\n", getpid());
  return execl("/bin/sh", "sh", "-c", "stress-ng --cpu 4 --timeout 30", NULL);
}

int main() {
  struct cgroup_cfg c = {
      .cpu_max_quota = 100000,
      .cpu_max_period = 100000,
      .mem_max = 100000000,
      .mem_swap_max = 0,
  };

  // Init cgroup context
  assert(!cgroup_init(&c));

  // Clone child process
  char *stack = malloc(STACK_SIZE);
  pid_t child_pid = clone(child_func, stack + STACK_SIZE, SIGCHLD, NULL);
  assert(child_pid != -1);

  // Add child to cgroup
  assert(!add_to_cgroup(child_pid, &c));

  printf("Parent PID: %d\n", getpid());
  waitpid(child_pid, NULL, 0);

  // Cleanup
  assert(!cgroup_remove(&c));
  free(stack);
  return 0;
}
