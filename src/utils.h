#ifndef UTILS_H
#define UTILS_H

#define SANDBOX_LOG(...) fprintf(stdout, "[+] " __VA_ARGS__)

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

#endif /* UTILS_H */
