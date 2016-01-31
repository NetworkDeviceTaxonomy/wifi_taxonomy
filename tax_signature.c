#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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
  } u;
} __attribute__ ((packed));

#define ASSOC_REQ         0
#define PROBE_REQ         4


/* from hostap/src/ap/taxonomy.c */

/* Copy a string with no funny schtuff allowed; only alphanumerics. */
static void no_mischief_strncpy(char *dst, const char *src, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) {
    unsigned char s = src[i];
    int is_lower = (s >= 'a' && s <= 'z');
    int is_upper = (s >= 'A' && s <= 'Z');
    int is_digit = (s >= '0' && s <= '9');
    if (is_lower || is_upper || is_digit) {
      /* TODO: if any manufacturer uses Unicode within the
       * WPS header, it will get mangled here. */
      dst[i] = s;
    } else {
      /* note that even spaces will be transformed to underscores,
       * so 'Nexus 7' will turn into 'Nexus_7'. This is deliberate,
       * to make the string easier to parse. */
      dst[i] = '_';
    }
  }
}

static int get_wps_name(char *name, size_t name_len,
    const u8 *data, size_t data_len)
{
  /* Inside the WPS IE are a series of sub-IEs, using two byte IDs
   * and two byte lengths. We're looking for the model name, if
   * present. */
  while (data_len >= 4) {
    u16 id, elen;
    id = (data[0] << 8) | data[1];
    elen = (data[2] << 8) | data[3];
    data += 4;
    data_len -= 4;

    if (elen > data_len) {
      return 0;
    }

    if (id == 0x1023) {
      /* Model name, like 'Nexus 7' */
      size_t n = (elen < name_len) ? elen : name_len;
      no_mischief_strncpy(name, (const char *)data, n);
      return n;
    }

    data += elen;
    data_len -= elen;
  }

  return 0;
}

static void ie_to_string(char *fstr, size_t fstr_len,
                         const char *capability,
                         const u8 *ie, size_t ie_len)
{
  size_t flen = fstr_len - 1;
  char htcap[7 + 4 + 1];  // ",htcap:" + %04hx + trailing NUL
  char htagg[7 + 2 + 1];  // ",htagg:" + %02hx + trailing NUL
  char htmcs[7 + 8 + 1];  // ",htmcs:" + %08x + trailing NUL
  char vhtcap[8 + 8 + 1];  // ",vhtcap:" + %08x + trailing NUL
  char vhtrxmcs[10 + 8 + 1];  // ",vhtrxmcs:" + %08x + trailing NUL
  char vhttxmcs[10 + 8 + 1];  // ",vhttxmcs:" + %08x + trailing NUL
  char intwrk[8 + 2 + 1];  // ",intwrk:" + %02hx + trailing NUL
  #define MAX_EXTCAP  254
  char extcap[8 + (2 * MAX_EXTCAP) + 1];  // ",extcap:" + hex + trailing NUL
  char txpow[7 + 4 + 1];  // ",txpow:" + %04hx + trailing NUL
  #define WPS_NAME_LEN    32
  char wps[WPS_NAME_LEN + 5 + 1];  // room to prepend ",wps:" + trailing NUL
  int num = 0;

  memset(htcap, 0, sizeof(htcap));
  memset(htagg, 0, sizeof(htagg));
  memset(htmcs, 0, sizeof(htmcs));
  memset(vhtcap, 0, sizeof(vhtcap));
  memset(vhtrxmcs, 0, sizeof(vhtrxmcs));
  memset(vhttxmcs, 0, sizeof(vhttxmcs));
  memset(intwrk, 0, sizeof(intwrk));
  memset(extcap, 0, sizeof(extcap));
  memset(txpow, 0, sizeof(txpow));
  memset(wps, 0, sizeof(wps));
  fstr[0] = '\0';

  while (ie_len >= 2) {
    u8 id, elen;
    char tagbuf[32];
    char *sep = (num++ == 0) ? "" : ",";

    id = *ie++;
    elen = *ie++;
    ie_len -= 2;

    if (elen > ie_len) {
      break;
    }

    if ((id == 221) && (elen >= 4)) {
      /* Vendor specific */
      int is_MSFT = (ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xf2);
      if (is_MSFT && ie[3] == 0x04) {
        /* WPS */
        char model_name[WPS_NAME_LEN + 1];
        const u8 *data = &ie[4];
        size_t data_len = elen - 4;
        memset(model_name, 0, sizeof(model_name));
        if (get_wps_name(model_name, WPS_NAME_LEN, data, data_len)) {
          snprintf(wps, sizeof(wps), ",wps:%s", model_name);
        }
      }

      snprintf(tagbuf, sizeof(tagbuf), "%s%d(%02x%02x%02x,%d)",
               sep, id, ie[0], ie[1], ie[2], ie[3]);
    } else {
      if ((id == 45) && (elen >= 2)) {
        /* HT Capabilities (802.11n) */
        u16 cap;
        memcpy(&cap, ie, sizeof(cap));
        snprintf(htcap, sizeof(htcap), ",htcap:%04hx",
                 le_to_host16(cap));
      }
      if ((id == 45) && (elen >= 3)) {
        /* HT Capabilities (802.11n), A-MPDU information */
        u8 agg;
        memcpy(&agg, ie + 2, sizeof(agg));
        snprintf(htagg, sizeof(htagg), ",htagg:%02hx", agg);
      }
      if ((id == 45) && (elen >= 7)) {
        /* HT Capabilities (802.11n), MCS information */
        u32 mcs;
        memcpy(&mcs, ie + 3, sizeof(mcs));
        snprintf(htmcs, sizeof(htmcs), ",htmcs:%08hx",
            le_to_host32(mcs));
      }
      if ((id == 191) && (elen >= 4)) {
        /* VHT Capabilities (802.11ac) */
        u32 cap;
        memcpy(&cap, ie, sizeof(cap));
        snprintf(vhtcap, sizeof(vhtcap), ",vhtcap:%08x",
                 le_to_host32(cap));
      }
      if ((id == 191) && (elen >= 8)) {
        /* VHT Capabilities (802.11ac), RX MCS information */
        u32 mcs;
        memcpy(&mcs, ie + 4, sizeof(mcs));
        snprintf(vhtrxmcs, sizeof(vhtrxmcs), ",vhtrxmcs:%08x",
                 le_to_host32(mcs));
      }
      if ((id == 191) && (elen >= 12)) {
        /* VHT Capabilities (802.11ac), TX MCS information */
        u32 mcs;
        memcpy(&mcs, ie + 8, sizeof(mcs));
        snprintf(vhttxmcs, sizeof(vhttxmcs), ",vhttxmcs:%08x",
                 le_to_host32(mcs));
      }
      if ((id == 107) && (elen >= 1)) {
        /* Interworking */
        snprintf(intwrk, sizeof(intwrk), ",intwrk:%02hx", *ie);
      }
      if (id == 127) {
        /* Extended Capabilities */
        int i;
        int len = (elen < MAX_EXTCAP) ? elen : MAX_EXTCAP;
        char *p = extcap;

        p += snprintf(extcap, sizeof(extcap), ",extcap:");
        for (i = 0; i < len; ++i) {
          int lim = sizeof(extcap) - strlen(extcap);
          p += snprintf(p, lim, "%02x", *(ie + i));
        }
      }
      if ((id == 33) && (elen == 2)) {
        /* TX Power */
        u16 p;
        memcpy(&p, ie, sizeof(p));
        snprintf(txpow, sizeof(txpow), ",txpow:%04hx",
                 le_to_host16(p));
      }

      snprintf(tagbuf, sizeof(tagbuf), "%s%d", sep, id);
    }

    strncat(fstr, tagbuf, flen);
    flen = fstr_len - strlen(fstr) - 1;

    ie += elen;
    ie_len -= elen;
  }

  if (capability) {
    strncat(fstr, capability, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(htcap)) {
    strncat(fstr, htcap, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(htagg)) {
    strncat(fstr, htagg, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(htmcs)) {
    strncat(fstr, htmcs, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(vhtcap)) {
    strncat(fstr, vhtcap, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(vhtrxmcs)) {
    strncat(fstr, vhtrxmcs, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(vhttxmcs)) {
    strncat(fstr, vhttxmcs, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(txpow)) {
    strncat(fstr, txpow, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(intwrk)) {
    strncat(fstr, intwrk, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(extcap)) {
    strncat(fstr, extcap, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }
  if (strlen(wps)) {
    strncat(fstr, wps, flen);
    flen = fstr_len - strlen(fstr) - 1;
  }

  fstr[fstr_len - 1] = '\0';
}


int usage(const char *progname)
{
  fprintf(stderr, "usage: %s -f pcap\n", progname);
  exit(1);
}


int main(int argc, char **argv)
{
  int opt;
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr hdr;
  const uint8_t *pkt;
  const char *filename = NULL;
  char mac[18];
  char probe_sig[4096] = {0};
  char assoc_sig[4096] = {0};

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

  if ((handle = pcap_open_offline(filename, errbuf)) == NULL) {
    perror("Cannot open pcap file");
    exit(1);
  }

  while ((pkt = pcap_next(handle, &hdr)) != NULL) {
    struct ieee80211_radiotap_hdr *rtap;
    struct ieee80211_mgmt *mlme;
    uint16_t fc;
    int type, subtype;
    uint8_t *ie;
    size_t ie_len;

    rtap = (struct ieee80211_radiotap_hdr *)pkt;
    mlme = (struct ieee80211_mgmt *)(pkt + rtap->it_len);
    fc = le_to_host16(mlme->frame_control);
    type = (fc >> 2) & 0x0003;
    subtype = (fc >> 4) & 0x000f;

    if (type == 0 && subtype == ASSOC_REQ) {
      char cap[5 + 4 + 1];  // ",cap:" + %04x + trailing NUL

      snprintf(cap, sizeof(cap), ",cap:%04hx", mlme->u.assoc_req.cap);
      ie = mlme->u.assoc_req.variable;
      ie_len = hdr.caplen - (ie - (const uint8_t *)mlme) - rtap->it_len - 4;
      ie_to_string(assoc_sig, sizeof(assoc_sig), cap, ie, ie_len);
    }

    if (type == 0 && subtype == PROBE_REQ) {
      snprintf(mac, sizeof(mac), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
          mlme->sa[0], mlme->sa[1], mlme->sa[2],
          mlme->sa[3], mlme->sa[4], mlme->sa[5]);

      ie = mlme->u.probe_req.variable;
      ie_len = hdr.caplen - (ie - (const uint8_t *)mlme) - rtap->it_len - 4;
      ie_to_string(probe_sig, sizeof(probe_sig), NULL, ie, ie_len);
    }
  }

  printf("%s wifi3|probe:%s|assoc:%s\n", mac, probe_sig, assoc_sig);

  if (strlen(probe_sig) && strlen(assoc_sig) && strlen(mac)) {
    exit(0);
  }

  exit(1);
}
