#include <pcap.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <stdint.h>

#include <iostream>
#include <vector>

#define BEACON  0b1000
#define MANAGE  0b00
#define _2GHZ   0b0000000100000000
#define _5GHZ   0b0000000010000000

#define MAC_STR "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n"
#define MAC_ARG(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]

using namespace std;

typedef struct _pre_flag{
    uint32_t flags[3];
} pre_flag;

typedef struct _radio_header {
    uint8_t ver;
    uint8_t pad;
    uint16_t hdr_len;
    pre_flag pflags;
    uint8_t flags;
    uint8_t dRate;
    uint16_t cFrequency;
    uint16_t cFlags;
    uint8_t signal;
    uint16_t sQuality;
    uint16_t RXFlags;
    uint8_t aSignal1;
    uint8_t antenna1;
    uint8_t aSignal2;
    uint8_t antenna2;
} radio_header;

typedef struct _beacon_frame {
    uint8_t ver:2;
    uint8_t type:2;
    uint8_t subType:4;
    uint8_t flags;
    uint16_t dur; // ?
    uint8_t rmac[6];
    uint8_t tmac[6];
    uint8_t bssid[6];
    uint16_t seq;
} beacon_frame;

typedef struct _beacon {
    radio_header *rHdr;
    beacon_frame *bFrm;
    uint32_t bCnt;
} beacon;

vector<beacon*> BEACON_VEC;
vector<char *>  NAME;

void usage(){
    puts("syntax : airodump <interface>");
    puts("sample : airodump wlan0");
}

void error(const char *msg) {
    warnx("Error: %s\n", msg);
    exit(-1);
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

void airodump(uint8_t *packet, uint32_t size) {
    beacon *bPtr;
    radio_header *rHdrPtr;
    beacon_frame *bFrmPtr;
    bool state = true;
    char name[0x400];
    char *nPtr = NULL;
    uint8_t tL;
    uint32_t idx = 0;
    vector<char *>::iterator nvPtr;

    //dump((unsigned char*)packet, size);
    rHdrPtr = (radio_header*)calloc(1, sizeof(radio_header) + 1);
    bFrmPtr = (beacon_frame*)calloc(1, sizeof(beacon_frame) + 1);
    bPtr    = (beacon*)calloc(1, sizeof(beacon) + 1);

    if(!rHdrPtr || !bFrmPtr || !bPtr) error("failed to allocate heap");

    memset(name, '\0', sizeof(name));
    memcpy(rHdrPtr, packet, sizeof(radio_header));
    memcpy(bFrmPtr, packet+32, sizeof(beacon_frame));

    if(bFrmPtr->type != MANAGE || bFrmPtr->subType != BEACON) state = false; 
    //dump((unsigned char*)bFrmPtr, sizeof(beacon_frame)); 
    //dump((unsigned char*)rHdrPtr, sizeof(radio_header));
    //printf("type: %d\n", bFrmPtr->type);
    //printf("subtype: %d\n", bFrmPtr->subType);

    if(state) {
        tL = *(packet+0x45);
        bPtr->rHdr = rHdrPtr;
        bPtr->bFrm = bFrmPtr;
        strncpy(name, (const char*)packet+0x46, tL);
        for(nvPtr = NAME.begin(); nvPtr!= NAME.end(); ++nvPtr) {
            if(strncmp(*nvPtr, name, 0x400) == 0) {
                state = false;
                break;
            }
            ++idx;
        }
        if(!state) {
            auto tmp1 = BEACON_VEC[idx]->rHdr;
            auto tmp2 = BEACON_VEC[idx]->bFrm;
            ++BEACON_VEC[idx]->bCnt;
            BEACON_VEC[idx]->rHdr = bPtr->rHdr;
            BEACON_VEC[idx]->bFrm = bPtr->bFrm;
            rHdrPtr = tmp1;
            bFrmPtr = tmp2;
        } else {
            bPtr->bCnt = 1;
            nPtr = strdup(name);
            NAME.push_back(nPtr);
            BEACON_VEC.push_back(bPtr);
        }
    } 
    if(!state) {
        free(nPtr);
        free(bPtr);
        free(rHdrPtr);
        free(bFrmPtr);
    }
}  

void print() {
    system("clear");
    vector<char *>::iterator nvPtr;
    vector<beacon *>::iterator bvPtr;
    char *channel;
    puts("==================[BEACONS :)]=====================");
    for(nvPtr = NAME.begin(), bvPtr = BEACON_VEC.begin(); nvPtr != NAME.end(), bvPtr != BEACON_VEC.end(); ++nvPtr, ++bvPtr) {
        channel = "IDK";
        if( (*bvPtr)->rHdr->cFlags & _2GHZ)        channel = "2GHZ";
        else if ( (*bvPtr)->rHdr->cFlags & _5GHZ)  channel = "5GHZ";
        cout << "ESSID: " << *nvPtr << endl;
        cout << "BSSID: ";
        printf(MAC_STR, MAC_ARG((*bvPtr)->bFrm->bssid));
        cout << "BEACONS: " << (*bvPtr)->bCnt << endl;
        cout << "CHANNEL: " << channel << endl;
    }
    puts("===================================================");
}

int main(int argc, const char* argv[]) {

    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *iface;
    const u_char *packet;
    struct pcap_pkthdr* header;
    const uint8_t *data;

	if (argc != 2) {
		usage();
		return -1;
	}

	iface = argv[1];

	pcap = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "couldn't open device %s(%s)\n", iface, errbuf);
		return -1;
	}

    while(true) {
        int res = pcap_next_ex(pcap, &header, &packet);
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
            error("pcap_next_ex error");
        airodump((uint8_t*)packet, header->caplen);
        print();
    }


	pcap_close(pcap);
}