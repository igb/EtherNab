#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>



/* HTTP Response struct */
 
struct http_response {
	int status;
	char* mime_type;
		
};

struct list_node {
	char* data;
	struct list_node *next;
};


/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6



/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};


/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};


#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};





char *retrieve_payload(const u_char *payload, int length) {
	
	FILE *file; 
	file = fopen("/tmp/file.gif","a+"); 

	
	char* first_header= malloc(length);
	char* img_payload= malloc(length);

	int is_http=0;
	int is_gif=0;
	int is_jpg=0;
	int previous_sequence_was_clrf=0;
	int is_html_entity=0;
	//int header_count=0;
	
	int i;
	
	for(i = 0; i < length; i++) {
		
		if (is_html_entity) {
			for(;i < length; i++) {
			 fwrite(payload, 1, 1, file);
				payload++;
			}
			printf("\nis a gif %d via http %d", is_gif, is_http);
			printf("\nis a jpg %d via http %d", is_jpg, is_http);


			fclose(file);
			return img_payload;
		}
		if (isprint(*payload)) {
			printf("%c", *payload);
			u_char* mychar= malloc(2);
			sprintf(mychar, "%c", *payload);
			strcat(first_header,mychar);
			previous_sequence_was_clrf=0;
			
		} else {
			
			char* mychar= malloc(2);
			sprintf(mychar, "%c", *payload);
			
		
			int c=*payload;
			
			int c2=-1;
			
			if (c == 13) {
				i++;
				payload++;
				c2=*payload;
				if (c2 == 10) {
					if (previous_sequence_was_clrf==1) {
						is_html_entity=1;
					}
					
					
					if (strcmp(first_header, "HTTP/1.1 200 OK") == 0) {
						//printf("\n\n%s\n", "It's HTTP");
						is_http=1;
						
					}
					
					if (strncmp(first_header, "Content-Type: image/gif", 23) == 0) {
						//printf("\n\n%s\n", "It's a GIF");
						is_gif=1;

					}
					
					
					if (strncmp(first_header, "Content-Type: image/jpeg", 24) == 0) {
						//printf("\n\n%s\n", "It's a GIF");
						is_jpg=1;
						
					}
					
					
					//free(first_header);
					first_header= malloc(length);
					
					//header_count++;
					printf("\n");
					previous_sequence_was_clrf=1;
				}
			} else {
				
			//	char* mychar= malloc(2);
			//	sprintf(mychar, "%c", *payload);
				
			
				
				//printf("%d", *payload);
				previous_sequence_was_clrf=0;

			}
			
			
			
		}
		payload++;
	}	
		printf("\nis a gif %d via http %d", is_gif, is_http);
	fclose(file); /*done!*/ 

	if (is_gif && is_http) {
		
		
		return img_payload;
		
		
	} else {
		return first_header;
	}
}





void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	
	/* Print its length */
//	printf("Jacked a packet with length of [%d]\n", header->len);
//	printf("Jacked a packet with cap length of [%d]\n", header->caplen);
	
	
	
	
	/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
	
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */
	
	u_int size_ip;
	u_int size_tcp;
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	
	
	
	//printf("Packet %d", packet);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	printf("\n===START PACKET==================================================================\n");

	
	/* print source and destination IP addresses */
	printf("\n\nIP HEADERS:\n");
	printf("From: %s\n", inet_ntoa(ip->ip_src));
	printf("To: %s\n", inet_ntoa(ip->ip_dst));
	printf("TTL: %d \n",(ip->ip_ttl));
	printf("Protocol: %d\n",(ip->ip_p));
	printf("Checksum: %d\n",(ip->ip_sum));
	printf("TOS: %d \n",(ip-> ip_tos));
	printf("Total Length: %d \n",(ip-> ip_len));
	printf("Identification: %d \n",(ip->ip_id));
	printf("Fragment Offset: %d \n",(ip->ip_off));	
	printf("Version: %d\t\n\n",(ip->ip_vhl >> 4));
	
	
	
	
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	
	printf("\n\nTCP HEADERS:\n");
	printf("Source Port: %d \n",(tcp->th_sport));
	printf("Dest. Port: %d \n",(tcp->th_dport));
	printf("Sequence Number: %u \n",(tcp->th_seq));
	printf("Ack Number: %u \n\n",(tcp->th_ack));

	
	
	
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
	//printf("payload size?: %d\n", packet + SIZE_ETHERNET + size_ip + size_tcp);
	//printf("payload size?: %d\n", size_payload);
	char* first_header=malloc(size_payload);
	first_header=retrieve_payload(payload, size_payload);
	printf("\n	===END PACKET==================================================================\n");
	
	
}





int main (int argc, const char * argv[]) {
	
	const char *dev = argv[1];
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	pcap_t *handle;			/* Session handle */

	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";	/* The filter expression */
	

	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (dev == NULL) {
		printf("Device was not entered on commandline!");
	
	}
	
	printf("Device: %s\n", dev);
	
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
		return -1;
	}
		

	
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}


	pcap_loop(handle, 1000, handle_packet, "igb");	



	
	

	/* And close the session */
	pcap_close(handle);
	
	return(0);
	
	
}
