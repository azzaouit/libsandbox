#ifndef FS_H
#define FS_H

#include <dirent.h>

struct fs_cfg {
  /* Path to sandbox root.
   * This path must point to a rootfs
   * made with e.g. debootstrap.
   */
  char root_dir[PATH_MAX];

  /* NULL-terminated array of paths to bind mount.
   * Paths should have a :ro or :rw suffix (e.g., /home:ro).
   * NULL if no bind_mounts desired.
   */
  const char **bind_mounts;
};

/* Init and mount the isolated fs */
int fs_init(const struct fs_cfg *const);

/* Preform pivot root into the isolated fs (from within the setup process) */
int fs_proot(const struct fs_cfg *const c);

/* Unmount and Remove the root sandbox directory */
void fs_remove(const struct fs_cfg *const);

#endif /* FS_H */
