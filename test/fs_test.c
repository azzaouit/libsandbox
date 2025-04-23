#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "fs.h"

#define STACK_SIZE (1024 * 1024)

// Sandboxed process
int child_func(void *arg) {
  struct fs_cfg *f = (struct fs_cfg *)arg;
  printf("Child PID: %d\n", getpid());
  assert(!fs_init(f));
  assert(!fs_proot(f));
  return execl("/bin/sh", "/bin/sh", NULL);
}

int main() {
  struct fs_cfg f = {
      .root_dir = "/mnt/sandbox",
      .bind_mounts = NULL,
  };

  // Clone child process
  char *stack = malloc(STACK_SIZE);
  pid_t child_pid = clone(child_func, stack + STACK_SIZE, SIGCHLD, &f);
  assert(child_pid != -1);

  printf("Parent PID: %d\n", getpid());
  waitpid(child_pid, NULL, 0);

  // Cleanup
  fs_remove(&f);
  free(stack);

  return 0;
}
