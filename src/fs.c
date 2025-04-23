#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "fs.h"
#include "utils.h"

static void __unmount(const char *path) {
  char subpath[PATH_MAX];
  struct dirent *entry;
  DIR *dir = opendir(path);
  if (dir) {
    while ((entry = readdir(dir)) != NULL) {
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
        continue;
      snprintf(subpath, sizeof(subpath), "%s/%s", path, entry->d_name);
      struct stat st;
      if (lstat(subpath, &st) == 0 && S_ISDIR(st.st_mode)) {
        __unmount(subpath);
      }
    }
    closedir(dir);
    umount2(path, MNT_DETACH | UMOUNT_NOFOLLOW);
  }
}

int __mount_user_dirs(const char **dirs, const char *new_root) {
  int ret;
  char *spec, *mode, path[PATH_MAX], target[PATH_MAX];
  for (const char **d = dirs; *d; ++d) {
    spec = (char *)*d;
    mode = strstr(spec, ":ro") ? "ro" : "rw";

    /* Extract actual host directory without suffix */
    strncpy(path, spec, PATH_MAX - 1);
    char *sep = strchr(path, ':');
    if (sep)
      *sep = '\0';

    /* Create the target directory in the new root */
    snprintf(target, PATH_MAX, "%s%s", new_root, path);
    if (mkdir(target, 0755) != 0 && errno != EEXIST) {
      perror("mkdir");
      return ret;
    }

    /* Bind mount host directory into the new root */
    if ((ret = mount(path, target, NULL, MS_BIND | MS_REC, ""))) {
      perror("mount");
      return ret;
    }

    /* If :ro, remount as read-only */
    if (!strcmp(mode, "ro") &&
        (ret = mount(NULL, target, NULL,
                     MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, ""))) {
      perror("mount");
      return ret;
    }

    SANDBOX_LOG("Mounted %s -> %s (%s)\n", path, target, mode);
  }

  return 0;
}

int fs_init(const struct fs_cfg *const c) {
  int ret;
  char path[PATH_MAX << 1];

  /* Enter a private mount namespace */
  if ((ret = unshare(CLONE_NEWNS))) {
    perror("unshare");
    return ret;
  }

  /* Create old root */
  snprintf(path, PATH_MAX << 1, "%s/.old_root", c->root_dir);
  if ((ret = mkdir(path, 0755)) && errno != EEXIST) {
    perror("mkdir");
    return ret;
  }
  SANDBOX_LOG("Creating path %s\n", path);

  /* Bind mount new_root onto itself to make it a mount point */
  SANDBOX_LOG("Creating mount point %s\n", c->root_dir);
  if ((ret = mount(c->root_dir, c->root_dir, "bind", MS_BIND | MS_REC, "")) <
      0) {
    perror("mount");
    return ret;
  }

  /* Make all mounts private to avoid propagating to host */
  SANDBOX_LOG("Isolating mounts\n");
  if ((ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) < 0) {
    perror("mount");
    return ret;
  }

  return c->bind_mounts ? __mount_user_dirs(c->bind_mounts, c->root_dir) : 0;
}

int fs_proot(const struct fs_cfg *const c) {
  int ret;

  /* Pivot into new root */
  SANDBOX_LOG("Pivoting into %s\n", c->root_dir);
  if ((ret = chdir(c->root_dir))) {
    perror("chdir");
    return ret;
  }
  if ((ret = syscall(SYS_pivot_root, ".", ".old_root"))) {
    perror("pivot_root");
    return ret;
  }

  /* Change into new root */
  if ((ret = chdir("/"))) {
    perror("chdir");
    return ret;
  }

  /* Unmount and remove old root */
  SANDBOX_LOG("Unmounting and removing old root\n");
  if ((ret = umount2("/.old_root", MNT_DETACH))) {
    perror("umount2");
    return ret;
  }
  if ((ret = rmdir("/.old_root"))) {
    perror("rmdir");
    return ret;
  }

  /* Mount procfs */
  SANDBOX_LOG("Mounting procfs\n");
  if ((ret = mkdir("/proc", 0555) && errno != EEXIST)) {
    perror("mkdir");
    return ret;
  }
  if ((ret = mount("proc", "/proc", "proc", 0, ""))) {
    perror("mount");
    return ret;
  }

  return 0;
}

void fs_remove(const struct fs_cfg *const c) {
  SANDBOX_LOG("Unmounting %s\n", c->root_dir);
  __unmount(c->root_dir);
}
