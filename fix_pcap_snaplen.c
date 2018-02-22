/*
 * Copyright 2018 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * https://github.com/the-tcpdump-group/libpcap/commit/f983e075fbef40fe12323c4dd8f85c88eaf0f789
 * added a check of the pcap file's snaplen field, that it not exceed the
 * MAXIMUM_SNAPLEN of 256k or it would print an error and exit. 10/2015
 *
 * https://github.com/the-tcpdump-group/libpcap/commit/2be9c29d45fb1fab8e9549342a30c160b7dea3e1
 * softened the check somewhat, making it print and error and truncate the
 * length it would allow to MAXIMUM_SNAPLEN but not exit. 5/2017
 *
 * As of 2/2018, there are a number of Linux distributions which contain the
 * first but not the second, so libpcap will exit if it finds a snaplen bigger
 * than 256k.
 *
 * Many pcaps in this repo were captured using Apple's Wi-Fi Diagnostics, which
 * sets the snaplen to 512k, though there are no packets in any pcap which
 * are more than a few hundred bytes. We used this program to rewrite the
 * snaplen of files checked into the repository.
 */

#include <endian.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct {
  uint32_t magic;          /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} pcap_file_hdr_t;
#define PCAP_MAGIC  0xa1b2c3d4
#define MAXIMUM_SNAPLEN (256*1024)


int usage(const char *progname)
{
  fprintf(stderr, "usage: %s -f pcap\n", progname);
  exit(1);
}


void write_pcap_header(int f, pcap_file_hdr_t *hdr)
{
  if (lseek(f, 0, SEEK_SET) != 0) {
    perror("Unable to lseek pcap file");
    exit(1);
  }
  if (write(f, hdr, sizeof(*hdr)) != sizeof(*hdr)) {
    fprintf(stderr, "Failed to write updated pcap header.\n");
    exit(1);
  }
}


int main(int argc, char **argv)
{
  int opt, f;
  const char *filename = NULL;
  pcap_file_hdr_t hdr;
  uint32_t magic_be = htobe32(PCAP_MAGIC);
  uint32_t magic_le = htole32(PCAP_MAGIC);
  uint32_t snaplen;

  while ((opt = getopt(argc, argv, "f:")) != -1) {
    switch(opt){
      case 'f':
        filename = optarg;
        break;
      default:
        usage(argv[0]);
        break;
    }
  }

  if (filename == NULL) {
    usage(argv[0]);
  }

  memset(&hdr, 0, sizeof(hdr));

  if ((f = open(filename, O_RDWR)) < 0) {
    perror("Cannot open file");
    exit(1);
  }
  if (read(f, &hdr, sizeof(hdr)) != sizeof(hdr)) {
    perror("Read failed");
    exit(1);
  }

  if (hdr.magic == magic_be) {
    snaplen = be32toh(hdr.snaplen);
    if (snaplen >= MAXIMUM_SNAPLEN) {
      hdr.snaplen = htobe32(MAXIMUM_SNAPLEN);
      write_pcap_header(f, &hdr);
    }
  } else if (hdr.magic == magic_le) {
    snaplen = le32toh(hdr.snaplen);
    if (snaplen >= MAXIMUM_SNAPLEN) {
      hdr.snaplen = htole32(MAXIMUM_SNAPLEN);
      write_pcap_header(f, &hdr);
    }
  } else {
    fprintf(stderr, "file: '%s' bad magic number: 0x%08x\n",
        filename, hdr.magic);
    exit(1);
  }

  exit(0);
}
