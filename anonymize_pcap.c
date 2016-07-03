/*
 * Copyright 2016 Google Inc. All rights reserved.
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


#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pcap.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <endian.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
#define le_to_host16  le16toh
#define le_to_host32  le32toh

struct ieee80211_radiotap_hdr {
  uint8_t it_version;
  uint8_t it_pad;
  uint16_t it_len;
  uint32_t it_present;
} __attribute__ ((packed));

struct ieee80211_mgmt {
  uint16_t frame_control;
  uint16_t duration;
  uint8_t da[6];
  uint8_t sa[6];
  uint8_t bssid[6];
  uint16_t seq_ctrl;
  union {
    struct {
      uint16_t cap;
      uint16_t listen;
      uint8_t variable[0];
    } __attribute__ ((packed)) assoc_req;
    struct {
      uint8_t variable[0];
    } __attribute__ ((packed)) probe_req;
    struct {
      uint32_t timestamp1;
      uint32_t timestamp2;
      uint16_t beacon_interval;
      uint16_t capabilities;
      uint8_t variable[0];
    } __attribute__ ((packed)) probe_resp;
    struct {
      uint32_t timestamp1;
      uint32_t timestamp2;
      uint16_t beacon_interval;
      uint16_t capabilities;
      uint8_t variable[0];
    } __attribute__ ((packed)) beacon;
  } u;
} __attribute__ ((packed));


#define ASSOC_REQ         0
#define PROBE_REQ         4
#define PROBE_RESP        5
#define BEACON            8
#define AUTH_REQ          11


int usage(const char *progname)
{
  fprintf(stderr, "usage: %s -f pcap\n", progname);
  exit(1);
}


/* from the very helpful https://eigenstate.org/notes/seccomp */
void enable_seccomp()
{
  #define ArchField offsetof(struct seccomp_data, arch)
  #define Allow(syscall) \
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##syscall, 0, 1), \
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

  struct sock_filter filter[] = {
    /* validate arch */
#ifdef __x86_64__
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),
    BPF_JUMP( BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
#else
#error Please add support for this architecture to the SECCOMP BPF code.
#endif

    /* load syscall */
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* list of allowed syscalls */
    Allow(exit_group),
    Allow(read),
    Allow(rename),
    Allow(write),
    Allow(stat),
    Allow(close),
    Allow(munmap),
    Allow(mmap),
    Allow(fstat),

    /* and if we don't match above, die */
    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
  };

  struct sock_fprog filterprog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter
  };

  /* set up the restricted environment */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)");
    exit(1);
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {
    perror("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)");
    exit(1);
  }
}


int is_broadcast_mac(uint8_t *mac)
{
  if (mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
      mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff) {
    return 1;
  }

  return 0;
}


void rewrite_ssid(uint8_t *ie, size_t ie_len)
{
  while (ie_len >= 2) {
    u8 id, elen;

    id = *ie++;
    elen = *ie++;
    ie_len -= 2;

    if (elen > ie_len) {
      break;
    }

    /* Replace SSID with 'XXXXXXXX' */
    if ((id == 0) && (elen > 0)) {
      int i;
      for (i = 0; i < elen; ++i) {
        ie[i] = 'X';
      }
    }

    ie += elen;
    ie_len -= elen;
  }
}


int main(int argc, char **argv)
{
  int opt;
  pcap_t *handle;
  pcap_dumper_t *outhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct rlimit lim;
  struct pcap_pkthdr hdr;
  const uint8_t *pkt;
  const char *filename = NULL;
  char outfile[PATH_MAX];
  struct stat in_st, out_st;
  FILE *pcapfp, *outfp;

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
  if ((pcapfp = fopen(filename, "rb")) == NULL) {
    perror("fopen(pcapfile)");
    exit(1);
  }

  snprintf(outfile, sizeof(outfile), "%s.anon", filename);
  if ((outfp = fopen(outfile, "wb")) == NULL) {
    perror("fopen(outfile)");
    exit(1);
  }

  /* No more files should be opened after this. */
  if (getrlimit(RLIMIT_NOFILE, &lim)) {
    perror("getrlimit");
    exit(1);
  }
  lim.rlim_cur = 0;
  if (setrlimit(RLIMIT_NOFILE, &lim)) {
    perror("setrlimit");
    exit(1);
  }

  /* We're about to parse packets, limit damage if we process
   * something malicious. */
  enable_seccomp();

  if ((handle = pcap_fopen_offline(pcapfp, errbuf)) == NULL) {
    perror("Cannot open pcap file");
    exit(1);
  }
  if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
    fprintf(stderr, "pcap file is not DLT_IEEE802_11_RADIO");
    exit(1);
  }

  if ((outhandle = pcap_dump_fopen(handle, outfp)) == NULL) {
    perror("Cannot open output pcap file");
    exit(1);
  }

  while ((pkt = pcap_next(handle, &hdr)) != NULL) {
    struct ieee80211_radiotap_hdr *rtap;
    struct ieee80211_mgmt *mlme;
    uint16_t fc, type, subtype;

    rtap = (struct ieee80211_radiotap_hdr *)pkt;
    mlme = (struct ieee80211_mgmt *)(pkt + rtap->it_len);
    fc = le_to_host16(mlme->frame_control);
    type = (fc >> 2) & 0x0003;
    subtype = (fc >> 4) & 0x000f;

    if (type == 0 && subtype == ASSOC_REQ) {
      uint8_t *ie = mlme->u.assoc_req.variable;
      size_t ie_len = hdr.caplen - (ie - (uint8_t *)mlme) - rtap->it_len - 4;
      rewrite_ssid(ie, ie_len);
    }

    if (type == 0 && subtype == PROBE_REQ) {
      uint8_t *ie = mlme->u.probe_req.variable;
      size_t ie_len = hdr.caplen - (ie - (uint8_t *)mlme) - rtap->it_len - 4;
      rewrite_ssid(ie, ie_len);
    }

    if (type == 0 && subtype == PROBE_RESP) {
      uint8_t *ie = mlme->u.probe_resp.variable;
      size_t ie_len = hdr.caplen - (ie - (uint8_t *)mlme) - rtap->it_len - 4;
      rewrite_ssid(ie, ie_len);
    }

    if (type == 0 && subtype == BEACON) {
      uint8_t *ie = mlme->u.beacon.variable;
      size_t ie_len = hdr.caplen - (ie - (uint8_t *)mlme) - rtap->it_len - 4;
      rewrite_ssid(ie, ie_len);
    }

    /* Anonymize the MAC addresses (but preserve OUI). */
    mlme->sa[3] = mlme->sa[4] = mlme->sa[5] = 0;
    if (!is_broadcast_mac(mlme->da)) {
      mlme->da[3] = mlme->da[4] = mlme->da[5] = 0;
    }
    if (!is_broadcast_mac(mlme->bssid)) {
      mlme->bssid[3] = mlme->bssid[4] = mlme->bssid[5] = 0;
    }

    pcap_dump((u_char *)outhandle, &hdr, pkt);
  }

  pcap_dump_close(outhandle);

  if (stat(filename, &in_st) || stat(outfile, &out_st)) {
    perror("stat");
    exit(1);
  }
  if (in_st.st_size != out_st.st_size) {
    fprintf(stderr, "Output truncated: got %jd bytes, want %jd bytes",
        out_st.st_size, in_st.st_size);
    exit(1);
  }
  if (rename(outfile, filename)) {
    perror("rename");
    exit(1);
  }

  exit(0);
}
