#ifndef CGROUP_H
#define CGROUP_H

#include <dirent.h>

struct cgroup_cfg {
  char path[PATH_MAX];
  size_t cpu_max_quota;
  size_t cpu_max_period;
  size_t mem_max;
  size_t mem_swap_max;
};

// Create cgroup directory and set resource limits
int cgroup_init(struct cgroup_cfg *c, const char *uuid);

// Add process to cgroup
int add_to_cgroup(pid_t pid, struct cgroup_cfg *c);

// Clean up cgroup
int cgroup_remove(struct cgroup_cfg *c);

#endif /* CGROUP_H */
