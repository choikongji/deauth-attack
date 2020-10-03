#include <mac.h>

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        u_int8_t        it_version ;     /* set to 0 */
        u_int8_t        it_pad ;
        u_int16_t       it_len ;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

#pragma pack(pop)
#pragma pack(push, 1)
struct deauth {
    uint16_t type;
    uint16_t dur;
    Mac des;
    Mac sou;
    Mac bss;
    uint16_t seq;
};

struct reason_code {
  uint16_t code;
};

struct deauthpacket {
    struct ieee80211_radiotap_header radio;
    uint8_t a[3];
    struct deauth dea;
    struct reason_code code;
};

#pragma pack(pop)

