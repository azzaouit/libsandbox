#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
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

int cgroup_set_cpu_max(struct cgroup_cfg *c) {
  char path[PATH_MAX];
  if (snprintf(path, PATH_MAX, "%s%s", c->path, CGROUP_CPU_MAX) < 0) {
    perror("snprintf failed");
    return errno;
  }

  FILE *cpu_file = fopen(path, "w");
  if (!cpu_file) {
    perror("fopen cpu.max failed");
    return errno;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup cpu max quota %lu %lu\n", c->cpu_max_quota,
              c->cpu_max_period);
#endif

  fprintf(cpu_file, "%lu %lu\n", c->cpu_max_quota, c->cpu_max_period);
  fclose(cpu_file);

  return 0;
}

int cgroup_set_mem_max(struct cgroup_cfg *c) {
  char path[PATH_MAX];
  if (snprintf(path, PATH_MAX, "%s%s", c->path, CGROUP_MEM_MAX) < 0) {
    perror("snprintf failed");
    return 0;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup mem max %ld\n", c->mem_max);
#endif

  FILE *mem_file = fopen(path, "w");
  if (!mem_file) {
    perror("fopen memory.max failed");
    return errno;
  }

  fprintf(mem_file, "%lu\n", c->mem_max);
  fclose(mem_file);

  return 0;
}

int cgroup_set_swap_max(struct cgroup_cfg *c) {
  char path[PATH_MAX];
  if (snprintf(path, PATH_MAX, "%s%s", c->path, CGROUP_SWAP_MAX) < 0) {
    perror("snprintf failed");
    return errno;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Setting cgroup swap max %ld\n", c->mem_swap_max);
#endif

  FILE *swap_file = fopen(path, "w");
  if (!swap_file) {
    perror("fopen memory.swap.max failed");
    return errno;
  }

  fprintf(swap_file, "%lu\n", c->mem_swap_max);
  fclose(swap_file);

  return 0;
}

int add_to_cgroup(pid_t pid, struct cgroup_cfg *c) {
  char path[PATH_MAX];
  if (snprintf(path, PATH_MAX, "%s%s", c->path, CGROUP_PROCS) < 0) {
    perror("snprintf failed");
    return errno;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Adding pid %d to cgroup %s\n", pid, c->path);
#endif

  FILE *procs_file = fopen(path, "w");
  if (!procs_file) {
    perror("fopen cgroup.procs failed");
    return errno;
  }

  fprintf(procs_file, "%d\n", pid);
  fclose(procs_file);

  return 0;
}

int cgroup_init(struct cgroup_cfg *c) {
  int ret = 0;
  char uuid[37];

  if ((ret = gen_uuid(uuid))) {
    SANDBOX_LOG("Failed to generate uuid\n");
    return ret;
  }

  if (snprintf(c->path, PATH_MAX, "%s%s", CGROUP_DIR, uuid) < 0) {
    perror("snprintf failed");
    return errno;
  }

#ifdef CGROUP_DEBUG
  SANDBOX_LOG("Creating cgroup %s\n", c->path);
#endif

  if (mkdir(c->path, CGROUP_DEFAULT_PERMS) < 0)
    return errno;

  if ((ret = cgroup_set_cpu_max(c)))
    goto err;

  if ((ret = cgroup_set_mem_max(c)))
    goto err;

  if ((ret = cgroup_set_swap_max(c)))
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
