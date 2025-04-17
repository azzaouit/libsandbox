#ifndef SCMP_H
#define SCMP_H

#include <fcntl.h>
#include <seccomp.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

struct scmp_rule {
  const char *name;       // Syscall name
  uint32_t action;        // SCMP_ACT_* value
  struct {                // Argument filters (max 3 per syscall)
    unsigned int arg;     // Argument index (0-5)
    enum scmp_compare op; // Comparison operator
    uint64_t a;           // First comparison value
    uint64_t b;           // Second comparison value (for masked ops)
  } args[3];
};

// Default allowlist
static struct scmp_rule default_rules[] __attribute__((unused)) = {
    // Basic I/O
    {"read", SCMP_ACT_ALLOW, {}},
    {"write", SCMP_ACT_ALLOW, {{0, SCMP_CMP_EQ, STDOUT_FILENO, 0}}},
    {"close", SCMP_ACT_ALLOW, {}},

    // Exit/termination
    {"exit_group", SCMP_ACT_ALLOW, {}},
    {"exit", SCMP_ACT_ALLOW, {}},

    // Memory management
    {"mmap",
     SCMP_ACT_ALLOW,
     {{2, SCMP_CMP_MASKED_EQ, PROT_EXEC, 0}}}, // No executable mappings
    {"brk", SCMP_ACT_ALLOW, {}},

    // Filesystem (read-only)
    {"openat", SCMP_ACT_ALLOW, {{2, SCMP_CMP_MASKED_EQ, O_ACCMODE, O_RDONLY}}},
    {"fstat", SCMP_ACT_ALLOW, {}}};

// Allowlist for network syscalls
static struct scmp_rule net_rules[] __attribute__((unused)) = {
    {"socket", SCMP_ACT_ALLOW, {}}, {"bind", SCMP_ACT_ALLOW, {}},
    {"listen", SCMP_ACT_ALLOW, {}}, {"accept", SCMP_ACT_ALLOW, {}},
    {"sendto", SCMP_ACT_ALLOW, {}}, {"recvfrom", SCMP_ACT_ALLOW, {}}};

// Apply an allowlist
int scmp_apply_rules(const struct scmp_rule *r, size_t n);

// Apply an allowlist
void scmp_setup_signal_handler();

#endif /* SCMP_H */
