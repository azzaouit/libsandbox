#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>
#include <unistd.h>

#include "cgroup.h"
#include "utils.h"

#define CGROUP_DEBUG 1
#define CGROUP_DEFAULT_PERMS (0755)
#define CGROUP_DIR "/sys/fs/cgroup/"
#define CGROUP_CPU_MAX "/cpu.max"
#define CGROUP_MEM_MAX "/memory.max"
#define CGROUP_SWAP_MAX "/memory.swap.max"
#define CGROUP_PROCS "/cgroup.procs"

#define CGROUP_WRITE_FILE(B, P, ...)                                           \
  do {                                                                         \
    char path[PATH_MAX];                                                       \
    if (snprintf(path, PATH_MAX, "%s%s", B, P) < 0) {                          \
      perror("snprintf failed");                                               \
      return errno;                                                            \
    }                                                                          \
    FILE *f = fopen(path, "w");                                                \
    if (!f) {                                                                  \
      perror("fopen failed");                                                  \
      return errno;                                                            \
    }                                                                          \
    fprintf(f, __VA_ARGS__);                                                   \
    fclose(f);                                                                 \
  } while (0)

int cgroup_set_cpu_max(struct cgroup_cfg *c) {
#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup cpu max quota %lu %lu\n", c->cpu_max_quota,
              c->cpu_max_period);
#endif
  CGROUP_WRITE_FILE(c->path, CGROUP_CPU_MAX, "%lu %lu\n", c->cpu_max_quota,
                    c->cpu_max_period);
  return 0;
}

int cgroup_set_mem_max(struct cgroup_cfg *c) {
#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup mem max %ld\n", c->mem_max);
#endif
  CGROUP_WRITE_FILE(c->path, CGROUP_MEM_MAX, "%lu\n", c->mem_max);
  return 0;
}

int cgroup_set_swap_max(struct cgroup_cfg *c) {
#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup swap max %ld\n", c->mem_swap_max);
#endif
  CGROUP_WRITE_FILE(c->path, CGROUP_SWAP_MAX, "%lu\n", c->mem_swap_max);
  return 0;
}

int add_to_cgroup(pid_t pid, struct cgroup_cfg *c) {
#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Adding pid %d to cgroup %s\n", pid, c->path);
#endif
  CGROUP_WRITE_FILE(c->path, CGROUP_PROCS, "%d\n", pid);
  return 0;
}

int cgroup_init(struct cgroup_cfg *c, const char *uuid) {
  int ret = 0;

  if (snprintf(c->path, PATH_MAX, "%s%s", CGROUP_DIR, uuid) < 0) {
    perror("snprintf failed");
    return errno;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Creating cgroup %s\n", c->path);
#endif

  if (mkdir(c->path, CGROUP_DEFAULT_PERMS) < 0)
    return errno;

  if ((c->cpu_max_quota || c->cpu_max_period) && (ret = cgroup_set_cpu_max(c)))
    goto err;

  if (c->mem_max && (ret = cgroup_set_mem_max(c)))
    goto err;

  if (c->mem_swap_max && (ret = cgroup_set_swap_max(c)))
    goto err;

  return 0;

err:
  cgroup_remove(c);
  return ret;
}

int cgroup_remove(struct cgroup_cfg *c) {
#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Removing cgroup %s\n", c->path);
#endif
  if (rmdir(c->path) < 0) {
    perror("cgroup cleanup failed");
    return errno;
  }
  return 0;
}
