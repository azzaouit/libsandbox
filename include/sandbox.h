#define _GNU_SOURCE
#ifndef SANDBOX_H
#define SANDBOX_H

#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/wait.h>

#include "cgroup.h"
#include "fs.h"
#include "scmp.h"
#include "utils.h"

/* Defines sandbox entrypoint */
typedef int (*sandboxed_func_t)(void);

struct sandbox {
  /* UUID generated for each sandbox */
  char uuid[37];
  /* Stack size */
  size_t stack_size;
  /* Cgroup config */
  struct cgroup_cfg c;
  /* Seccomp filters */
  struct scmp_rule *r;
  /* Number of seccomp filters */
  size_t nrules;
  /* File system config */
  struct fs_cfg f;
  /* Sandbox entry point. Can be used to execv some process. */
  sandboxed_func_t f_entry;
};

static int gen_uuid(char *uuid_str) {
  unsigned char bytes[16];

  if (getrandom(bytes, sizeof(bytes), 0) != sizeof(bytes)) {
    SANDBOX_LOG("Failed to get random bytes\n");
    return errno;
  }

  bytes[6] = (bytes[6] & 0x0F) | 0x40;
  bytes[8] = (bytes[8] & 0x3F) | 0x80;

  return snprintf(uuid_str, 37,
                  "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%"
                  "02x%02x%02x",
                  bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                  bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
                  bytes[12], bytes[13], bytes[14], bytes[15]) < 0;
}

static int sandbox_child(void *a) {
  int ret;
  struct sandbox *s = (struct sandbox *)a;
  SANDBOX_LOG("Child PID: %d\n", getpid());

  /* Setup and pivot into rootfs */
  if ((ret = fs_init(&s->f))) {
    SANDBOX_LOG("Failed to init file system\n");
    return ret;
  }
  if ((ret = fs_proot(&s->f))) {
    SANDBOX_LOG("Failed to pivot into file system\n");
    return ret;
  }

  /* Setup seccomp filters (if any) */
  if (s->r && s->nrules) {
    scmp_setup_signal_handler();
    if ((ret = scmp_apply_rules(s->r, s->nrules))) {
      SANDBOX_LOG("scmp_apply_rules failed\n");
      return ret;
    }
  }

  /* Jump to untrusted code here */
  SANDBOX_LOG("Executing untrusted code at %p\n", s->f_entry);
  return s->f_entry();
}

static int sandbox(struct sandbox *s) {
  SANDBOX_LOG("Parent PID: %d\n", getpid());

  int ret;
  char *stack = calloc(1, s->stack_size);
  if (!stack) {
    perror("calloc");
    return errno;
  }

  if ((ret = gen_uuid(s->uuid))) {
    SANDBOX_LOG("Failed to generate uuid\n");
    return ret;
  }

  if ((ret = cgroup_init(&s->c, s->uuid))) {
    SANDBOX_LOG("cgroup_init failed\n");
    return ret;
  }

  pid_t child_pid = clone(sandbox_child, stack + s->stack_size, SIGCHLD, s);
  if (child_pid == -1) {
    perror("clone");
    return errno;
  }

  if ((ret = add_to_cgroup(child_pid, &s->c))) {
    SANDBOX_LOG("add_to_cgroup failed\n");
    return errno;
  }

  waitpid(child_pid, NULL, 0);

  cgroup_remove(&s->c);
  fs_remove(&s->f);
  free(stack);
  return 0;
}

#endif /* SANDBOX_H */
