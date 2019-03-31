#include <pcap.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>


#define ETHERTYPE_IP  0x0800
#define TCP_TYPE 6

struct eth_header
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ip_header
{
    unsigned char Header_Length:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short len;
    unsigned short Identi;
    unsigned short ffo;
    unsigned char TTL;
    unsigned char protocol;
    unsigned short cheaksum;
    unsigned char sip[4];
    unsigned char dip[4];
};

struct tcp_header
{
    //    unsigned char sport[2];
    //    unsigned char dport[2];
    //    unsigned int sequence_number;
    //    unsigned int acknum;
    //    unsigned short Header_Length:4;
    //    unsigned short Reserved:4;
    //    unsigned short Flags:8;
    //    unsigned short window;
    //    unsigned short cheaksum;
    //    unsigned short Urgentpoint;

    unsigned char sport[2];
    unsigned char dport[2];
    unsigned int sequence_number;
    unsigned int acknum;
    unsigned char ns:1;
    unsigned char res:3;
    unsigned char Header_len:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short cheaksum;
    unsigned short urgentpoint;
};

//struct http_data;

void usage()
{
    printf("syntax: pcap_test <interface>\n");  //
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        usage();
        return -1;
    }

    char* dev = argv[1];  // network device's name a pointed variable
    char errbuf[PCAP_ERRBUF_SIZE];  //error message variable

    int i;  // for

    pcap_t* handle = pcap_open_live(dev,2048, 1, 1000, errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {

        struct pcap_pkthdr* header;  // header len
        const u_char* packet;   // packet data , hexa code can see vi
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0)
        {
            continue;
        }
        else if (res == -1 || res == -2)  // || -> or
        {
            break;
        }



        //MAC


        struct eth_header* ethh;

        ethh = (struct eth_header *)packet;


        printf("========Mac Address=======\n\n");


        printf("smac = ");

        for(i=0; i<=5; i++)
        {

            if(i>4)
            {
                printf("%02x", ethh->smac[i]);
                break;
            }

            printf("%02x:", ethh -> smac[i]);
        }

        printf("\n");


        printf("dmac = ");

        for(i=0; i<=5; i++)
        {
            if(i>4)
            {
                printf("%02x\n", ethh -> dmac[i]);
                break;
            }
            printf("%02x:", ethh -> dmac[i]);
        }

        printf("\n");


        // ip

        struct ip_header* iph;

        iph = (struct ip_header *)(packet+14);

        unsigned short eth_type;

        eth_type = ntohs(ethh->type);


        if((eth_type) == ETHERTYPE_IP)
        {
            printf("=======Next Protocol is IPv4=======\n\n");

            printf("sip = ");

            for(i=0; i<=3; i++)
            {
                if(i>2)
                {
                    printf("%d", iph -> sip[i]);
                    break;
                }

                printf("%d.", iph -> sip[i]);
            }

            printf("\n");


            printf("dip = ");


            for(i=0; i<=3; i++)
            {
                if(i>2)
                {
                    printf("%d\n", iph -> dip[i]);
                    break;
                }

                printf("%d.", iph -> dip[i]);
            }
        }

        else
        {
            printf("other protocol\n");
            return 0;
        }


        printf("\n");



        //tcp

        struct tcp_header* th;

        th = (struct tcp_header *)(packet+14+4*(iph->Header_Length));


        if((iph->protocol) == TCP_TYPE)
        {
            printf("=======Next Protocol is TCP=======\n\n");

            printf("sport = %d\n", ((th->sport[0])<<8)+(th->sport[1]));

            printf("dport = %d\n",((th->dport[0]<<8)+(th->dport[1])));

        }

        else
        {
            printf("Not Tcp\n");
            return 0;
        }


        printf("\n");


        //http





        const u_char* http_data;





        //     printf("len = %d\n", sizeof(http_data));


        //        hd = (packet+(iph->len)-((iph->Header_Length)<<2)-((th->Header_Length)<<2));


        http_data = (packet+14+4*(iph->Header_Length)+4*(th->Header_len));


        printf("=======HTTP DATA=======\n\n");



            printf("%s\n", http_data);


        //       break;


    }


    pcap_close(handle);

    return 0;

}



















