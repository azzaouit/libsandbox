#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scmp.h"
#include "utils.h"

int scmp_apply_rules(const struct scmp_rule *const r, size_t n) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
  if (!ctx) {
    perror("seccomp_init failed");
    return errno;
  }

  // Allow base architecture syscalls
  seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
  seccomp_arch_add(ctx, SCMP_ARCH_X86_64);

  for (size_t i = 0; i < n; ++i) {
    int nr = seccomp_syscall_resolve_name_arch(SCMP_ARCH_X86_64, r[i].name);
    if (nr == __NR_SCMP_ERROR) {
      SANDBOX_LOG("Unknown syscall: %s\n", r[i].name);
      return errno;
    }

    // Build argument filters
    struct scmp_arg_cmp filters[3] = {0};
    size_t j = 0;
    for (j = 0; j < 3; ++j) {
      if (r->args[j].op == 0)
        break; // No more filters
      filters[j].arg = r[i].args[j].arg;
      filters[j].op = r[i].args[j].op;
      filters[j].datum_a = r[i].args[j].a;
      filters[j].datum_b = r[i].args[j].b;
    }

    int rc = seccomp_rule_add_array(ctx, r->action, nr, j, filters);
    if (rc < 0) {
      SANDBOX_LOG("Failed to add %s rule: %s\n", r->name, strerror(-rc));
      return rc;
    }
  }

  if (seccomp_load(ctx) < 0) {
    perror("seccomp_load failed");
    return errno;
  }

  seccomp_release(ctx);
  return 0;
}

// Signal handler for SIGSYS (triggered by seccomp)
static void scmp_handle_sigsys(int signo, siginfo_t *info, void *ucontext) {
  const char msg[] = "\nSandbox violation: Blocked syscall detected\n"
                     "Syscall: %s (%d)\n"
                     "Architecture: 0x%x\n"
                     "Instruction pointer: %p\n";
  (void)signo;
  (void)ucontext;

  const char *syscall_name =
      seccomp_syscall_resolve_num_arch(SCMP_ARCH_X86_64, info->si_syscall);

  /* Use async-safe write to stderr */
  dprintf(STDERR_FILENO, msg, syscall_name, info->si_syscall, info->si_arch,
          info->si_call_addr);

  _exit(EXIT_FAILURE);
}

void scmp_setup_signal_handler() {
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO | SA_NODEFER;
  sa.sa_sigaction = scmp_handle_sigsys;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGSYS, &sa, NULL);
}
