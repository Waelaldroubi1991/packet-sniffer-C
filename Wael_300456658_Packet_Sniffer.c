
//Wael Aldroubi
//300456658

//.....................................................................................................//

//Packet Sniffer in C
//Code using decliration is at the buttom of the code, with websites used to understand and get parts of the code.

//.....................................................................................................//

//Needed libraries for the application (to handel IPV4/V6, TCP, UDP, ICMP, unknown)
#include <stdio.h>                      
#include <stdlib.h>                     
#include <errno.h>                      
#include <stdbool.h>                    
#include <string.h>                     
#include <sys/socket.h>                 
#include <arpa/inet.h>                  
#include </usr/include/netinet/ip.h>    
#include </usr/include/netinet/ip6.h>   
#include </usr/include/pcap/pcap.h>     
#include <net/ethernet.h>               
#include <netinet/in.h>                 
#include <netinet/if_ether.h>           
#include <netinet/ether.h>              
#include <netinet/tcp.h>           
#include <netinet/udp.h>             
#include <netinet/ip_icmp.h>          
#include <netinet/icmp6.h>

//.....................................................................................................//      

//Prototypes
void handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void handle_ipv6(int, int, const u_char*, char*);
void print_tcp (const u_char*, int*);
void print_udp (const u_char*, int*);
void print_payload (const u_char *, int);
void print_ipv4(char*, char*);
void print_icmp6(const u_char*, int*);
void print_ipv6();

//.....................................................................................................//

//Global Variables
//boolean for traffics and protocols
bool ipv4_bool = false;
bool ipv6_bool = false;
bool tcp_bool = false;
bool udp_bool = false;
bool icmp_bool = false;
bool other_traffic_bool = false;
bool unknown_protocol_bool = false;
//............................................//
//packets numbers to keep track of them, and headers length.
int packet_counter = 0;
int headerLength = 0;
//............................................//
//IPV6 source and destenation address declation.
char sourIP6[INET_ADDRSTRLEN];
char destIP6[INET_ADDRSTRLEN];

//.....................................................................................................//

//To handle packets and sort them depending on type.
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //Defining constructors to connect to packet headers (IPV4/v6 - TCP - UDP - ICMP - Ethernet)
    const struct ether_header *ethernet_header;
    const struct ip *ipv4_header;             
    const struct ip6_hdr *ipv6_header;         
    const struct tcphdr *tcp_header;          
    const struct udphdr *udp_header;          
    const struct icmphdr *icmp_header;          
    //............................................//
    //IPV4 source and destenation address declation.
    char sourIP4[INET_ADDRSTRLEN];
    char destIP4[INET_ADDRSTRLEN];
    //............................................//
    //Header length and counter defintion
    headerLength = header->len;
    ++packet_counter;
    //............................................//
    //Eithernet header and its size
    ethernet_header = (struct ether_header*)(packet);
    int size = 0;
    size += sizeof(struct ether_header);
    //............................................//
    //Switch to check packet type using protocol.
    switch(ntohs(ethernet_header->ether_type)){
	//IPv4 type.
	case ETHERTYPE_IP:
		if(ipv4_bool == false){
		    return;
		}
		//IPV4 header, source and destination addresses and its size.
		ipv4_header = (struct ip*)(packet + size);
		inet_ntop(AF_INET, &(ipv4_header->ip_src), sourIP4, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipv4_header->ip_dst), destIP4, INET_ADDRSTRLEN);
		size += sizeof(struct ip);
		//Original data (User data)
		u_char *payload;
		int dataLength = 0;
		//............................................//
		//Switch to check the IPV4 type of protocol (TCP-UDP-ICMPv4) 
		switch(ipv4_header->ip_p){
		    case IPPROTO_TCP://TCP
			if(tcp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			print_tcp(packet, &size);
			break;
		    case IPPROTO_UDP://UDP
			if(udp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			print_udp(packet, &size);
			break;
		    case IPPROTO_ICMP://ICMPv4  
			if(icmp_bool == false){
			    return;
			}
			print_ipv4(sourIP4, destIP4);
			printf("Protocol: ICMP \n"); 
			//ICMP size and header
			icmp_header = (struct icmphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			u_int type = icmp_header->type;
			//Error message to handle (Time to live) in case expired
			if(type == 11){
			    printf("TTL Expired! \n");
			}
			else if(type == ICMP_ECHOREPLY){
			    printf("ICMP Echo Reply! \n");
			}
			//Original data printing (User data).
			payload = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr));
			dataLength = header->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct icmphdr)); 
			printf("Payload: (%d bytes) \n", dataLength);
			printf("\n");
			print_payload(payload, dataLength);
			break;
		    //When the protocol is unknown.
		     default:
			if(unknown_protocol_bool == false){
			    return;
			}
			printf("Protocol: Unknown \n");
			break;
		}
		break;
	//............................................//	
	//In case it is IPV6 go to this section and will implement the next section (handle_ipv6).
	case ETHERTYPE_IPV6:
		if(ipv6_bool == false){
		    return;
		}
		//IPV6 header, source and distination addresses and size.
		ipv6_header = (struct ip6_hdr*)(packet + size); 
		inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
		//To treverse the headers.
		int nextheader = ipv6_header->ip6_nxt;
		size += sizeof(struct ip6_hdr);
		char string[100] = " ";
		handle_ipv6(nextheader, size, packet, string);
		break;
	//When the packet type is unknown
	default:
		if(other_traffic_bool == false){
		    return;
		}
		printf("Ether Type: Unknown \n");
		break;
    }
}

//.....................................................................................................//

//function for IPV6 packets.
void handle_ipv6(int header, int size, const u_char *packet, char *string)
{
	//Switch to check the IPV6 type of protocol (TCP-UDP-ICMPv6) 
    switch(header){
	//IPV6 routing control
	case IPPROTO_ROUTING:
		strcat(string, "ROUTING, ");
		struct ip6_rthdr* header = (struct ip6_rthdr*)(packet + size); 
		size+=sizeof(struct ip6_rthdr);
		print_ipv6(header->ip6r_nxt, size, packet, string);
		break;
	//IPV6 hop by hop control of hob limit
	case IPPROTO_HOPOPTS:
		strcat(string, "HOP-BY_HOP, ");
		struct ip6_hbh* header_hop = (struct ip6_hbh*)(packet + size); 
		size+=sizeof(struct ip6_hbh);
		print_ipv6(header_hop->ip6h_nxt, size, packet, string);
		break;
	//IPV6 fragmentation control
	case IPPROTO_FRAGMENT:
		strcat(string, "FRAGMENTATION, ");
		struct ip6_frag* header_frag = (struct ip6_frag*)(packet + size); 
		size+=sizeof(struct ip6_frag);
		print_ipv6(header_frag->ip6f_nxt, size, packet, string);
		break;
	//IPV6 destination choices.
	case IPPROTO_DSTOPTS:
		strcat(string, "Destination options, ");
		struct ip6_dest* header_dest = (struct ip6_dest*)(packet + size); 
		size+=sizeof(struct ip6_dest);
		print_ipv6(header_dest->ip6d_nxt, size, packet, string);
		break;
	case IPPROTO_TCP:	//TCP
		if(tcp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_tcp(packet, &size);
		break;
	case IPPROTO_UDP:	//UDP
		if(udp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_udp(packet, &size);
		break;
	case IPPROTO_ICMPV6:	//ICMPv6
		if(icmp_bool == false){
		    return;
		}
		print_ipv6();
		printf("%s \n", string);
		print_icmp6(packet, &size);
		break;
	default:	//Unknown
		if(unknown_protocol_bool == false){
		    return;
		}
		print_ipv6();
		printf("Protocol: Unknown \n");
		break;
    }
}

//.....................................................................................................//

//Function to print IPV4 packets.
void print_ipv4(char *source, char *dest)
{
    printf("\n");
    printf("Packet #: %d \n", packet_counter);
    printf("Ether Type: IPv4 \n");
    printf("From: %s \n", source);
    printf("To: %s \n", dest);
}

//.....................................................................................................//

//Function to print IPV6 packets.
void print_ipv6()
{
    printf("\n");
    printf("Packet #: %d \n", packet_counter);
    printf("Ether Type: IPv6 \n");
    printf("From: %s \n", sourIP6);
    printf("To: %s \n", destIP6);
    printf("Extension Headers:");
}

//.....................................................................................................//

//Function to print TCP packets.
void print_tcp(const u_char *packet, int *size)
{    
    const struct tcphdr* tcp_header;
    u_int sourPort, destPort;  
    u_char *payload;         
    int dataLength = 0;
    //TCP header, Source and Distination addresses
    tcp_header = (struct tcphdr*)(packet + *size);
    sourPort = ntohs(tcp_header->source);
    destPort = ntohs(tcp_header->dest);
    //User data (Payload)
    *size += tcp_header->doff*4;
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;
    //printing TCP
    printf("protocol: TCP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");
    //printing User data.
    print_payload(payload, dataLength);
}

//.....................................................................................................//

//Function to print UDP packets.
void print_udp(const u_char *packet, int *size)
{     
    const struct udphdr* udp_header;
    u_int sourPort, destPort; 
    u_char *payload;          
    int dataLength = 0;
    //UDP header, Source and Distination addresses
    udp_header = (struct udphdr*)(packet + *size);
    sourPort = ntohs(udp_header->source);
    destPort = ntohs(udp_header->dest);
    //User data (Payload)
    *size+=sizeof(struct udphdr);
    payload = (u_char*)(packet + *size);
    dataLength = headerLength - *size;
    //printing TCP
    printf("protocol: UDP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("\n");
    //printing User data.
    print_payload(payload, dataLength);
}

//.....................................................................................................//


//Function to print ICMPv6 packets.
void print_icmp6(const u_char *packet, int *size)
{
    printf("Protocol: ICMPv6 \n");
    u_char *payload;
    int dataLength = 0;
    //ICMPv6 header
    struct icmp6_hdr* header_icmp6 = (struct icmp6_hdr*)(packet+*size);
    //User data (Payload)
    payload = (u_char*)(packet + *size + sizeof(struct icmp6_hdr));
    dataLength = headerLength - *size + sizeof(struct icmp6_hdr); 
    //printing User data.
    printf("Payload: (%d bytes) \n", dataLength);
    print_payload(payload, dataLength);
}

//.....................................................................................................//

//Function to print User data (Payload).
void print_payload(const u_char *payload, int Size)
{
    int i , j;
    for(i = 0; i < Size; i++){
        if( i!=0 && i%16==0){
            printf("         ");
	    for(j = i - 16; j < i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
                    printf("%c",(unsigned char)payload[j]);
		}
                else{
		    printf(".");
		}
            }
            printf("\n");
        }
        if(i%16 == 0) printf("   ");
            printf(" %02X",(unsigned int)payload[i]);
                 
        if(i == Size - 1){
            for(j = 0; j < 15 - i%16; j++){
		printf("   ");
            }
            printf("         ");
            for(j = i - i%16; j <= i; j++){
                if(payload[j] >= 32 && payload[j] <= 128){
		    printf("%c",(unsigned char)payload[j]);
                }
                else{
		    printf(".");
                }
            }
            printf("\n" );
        }
    }
}

//.....................................................................................................//

//Main function to read pcapy file and return the output
//will return an error if the file reading is not correct
int main(int argc, char *argv[]) 
{
	//to read the file and handle the packet
    const char *fname = argv[1];   
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *handle;                
    //............................................//
    //in case if the pcapy file is missing or wrong format
    if(argc == 1){
	printf("Error: pcap file is missing! \n");
	printf("Please use following format command: $./eps [captured_file_name] \n");
	exit(EXIT_FAILURE);
    }
    //............................................//
    //Will read packet one by one.
    for(int i = 2; i < argc; i++){
	if(strcasecmp("IPV4", argv[i]) == 0){
	    ipv4_bool = true;
	}
	else if(strcasecmp("IPV6", argv[i]) == 0){
	    ipv6_bool = true;
	}
	else if(strcasecmp("TCP", argv[i]) == 0){
	    tcp_bool = true;
	}
	else if(strcasecmp("UDP", argv[i]) == 0){
	    udp_bool = true;
	}
	else if(strcasecmp("ICMP", argv[i]) == 0){
	    icmp_bool = true;
	}
	else if(strcasecmp("UNKNOWN", argv[i]) == 0){
	    unknown_protocol_bool = true;
	}
    }
    //............................................//
    //accept all traffic if no other options
    if(argc == 2){
	ipv4_bool = true;
	ipv6_bool = true;
	other_traffic_bool = true;
    }
    //............................................//
    if((ipv4_bool == true || ipv6_bool == true) && tcp_bool == false && udp_bool == false && icmp_bool == false && unknown_protocol_bool == false){
	tcp_bool = true;
	udp_bool = true;
	icmp_bool = true;
	unknown_protocol_bool = true;
    }
    //............................................//
    //In case the command is wrong.
    if(argc > 2){
	printf("Error: unrecognized command! \n");
	printf("Please use following format command: $./eps [captured_file_name] \n");
	exit(EXIT_FAILURE);
    }
    //............................................//
    //store the pcapy file in the handle variable
    handle = pcap_open_offline(fname, errbuf);
    //............................................//
    //In case the pacpy file has errors.
    if(handle == NULL){
	printf("pcap file [%s] with error %s \n", fname, errbuf);
	exit(EXIT_FAILURE);
    }
    //............................................//
    //To go trough pcapy file.
    pcap_loop(handle, 0, handle_packet, NULL);
    return 1;
}

//.....................................................................................................//

//Understanding and Some codes taken from:
//https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
//http://www.tcpdump.org/sniffex.c
//https://www.scribd.com/document/259948478/Packet-Sniffer-Code-in-C-Using-Sockets-Linux
//https://www.youtube.com/watch?v=O-tp0EYYMWg&t=505s
//https://www.youtube.com/watch?v=Js2_0955n3o

//.....................................................................................................//

/*
 * This C program is based on Tim Carstens' "sniffer.c" demonstration source code (http://www.tcpdump.org/sniffex.c), released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 */