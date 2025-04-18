#ifndef PING_H
#define PING_H

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "scmp.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Minimal allowlist for an icmp echo
static struct scmp_rule ping_rules[] = {
    {"socket", SCMP_ACT_ALLOW, {}}, {"sendto", SCMP_ACT_ALLOW, {}},
    {"write", SCMP_ACT_ALLOW, {}},  {"close", SCMP_ACT_ALLOW, {}},
    {"dup", SCMP_ACT_ALLOW, {}},    {"fcntl", SCMP_ACT_ALLOW, {}},
    {"fstat", SCMP_ACT_ALLOW, {}},  {"exit_group", SCMP_ACT_ALLOW, {}},
    {"getpid", SCMP_ACT_ALLOW, {}}, {"exit", SCMP_ACT_ALLOW, {}},
};

struct icmp_packet {
  struct icmphdr header;
  char payload[64];
};

unsigned short checksum(void *data, int len) {
  unsigned short *buf = data;
  unsigned int sum = 0;
  unsigned short result;
  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;
  if (len == 1)
    sum += *(unsigned char *)buf;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

int ping(char *dest_ip) {
  int sockfd;
  struct sockaddr_in dest_addr;

  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    perror("socket() failed");
    exit(1);
  }

  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);

  struct icmp_packet packet = {
      .header.type = ICMP_ECHO,
      .header.code = 0,
      .header.un.echo.id = getpid(),
      .header.un.echo.sequence = 0,
      .header.checksum = checksum(&packet, sizeof(packet)),
      .payload = {0},
  };

  // Send packet
  if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr,
             sizeof(dest_addr)) < 0) {
    perror("sendto() failed");
    return errno;
  }

  printf("ICMP Echo Request sent to %s\n", dest_ip);
  close(sockfd);
  return 0;
}

#endif /* PING_H */
