#ifdef HAVE_CONFIG_H
	#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <endian.h>
#include <ctype.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>


#define ETHERNET_HEADER_LENGTH 14
#define IP_HEADER_MIN_LENGTH 20
#define ARP_HEADER_LENGTH 8
#define TCP_HEADER_MIN_LENGTH 20
#define ICMP_HEADER_LENGTH 4
#define UDP_HEADER_LENGTH 8
#define MAC_ADDRESS_SIZE 6

#define INTERFACE	"wlan0"

typedef unsigned int size32;//32-bitowy typ danych
typedef unsigned short int size16; // definicja 16-bitowego typu danych
typedef unsigned char size8; //definicja 8-bitowego typu danych

union pakiet{
	struct dat_eth_arp *eth_arp;
	struct dat_eth_ip_udp *udp;
	struct dat_eth_ip_tcp *tcp;
	struct dat_eth_ip_icmp *icmp;
	struct dat_eth_dane *eth_dane;
	struct dat_eth_ip_dane *ip_dane;
};

/*
 * struktury listy
 */
struct list{
	struct list_item *pierwszy;
	struct list_item *ostatni;
	size16 eth_type;
	size16 ip_protocol;
};

struct list_item{
	struct list_item *nastepny;
	struct list_item *poprzedni;
	union pakiet *pakiet;
	size16 rozmiar;
};

//nag_ethernet 22 B
struct nag_ethernet {
		size8 destynation_address[6];
		size8 source_address[6];
		size16 type;
};

//nag_arp 8 B
struct nag_arp{
	size16 hardware_type;
	size16 protocol_type;
	size8 hardware_adresses_length;
	size8 protocol_adresses_length;
	size16 opcode;
};

//nag_ip 20 B
struct nag_ip{
	size8 IHL:4,
				  version:4;
	size8 ECN:2,
			DSCP:6;
	size16 total_length;
	size16 identification;
	size16 	fragmnet_offset:13,
			more_fragments:1,
			dont_fragment:1,
			reserved_bit:1;
	size8 time_to_live;
	size8 protocol;
	size16 header_checksum;
	size8 source_address[4];
	size8 destination_address[4];
	size8 *options;
};

//nag_tcp 20 B
struct nag_tcp{
	size16 source_port;
	size16 destination_port;
	size32 sequence_number;
	size32 acknowledgment_number;
	size8	NS:1,
			reserved:3,
			data_offset:4;
	size8  FIN:1,
			SYN:1,
			RST:1,
			PSH:1,
			ACK:1,
			URG:1,
			ECE:1,
			CWR:1;
	size16 window;
	size16 checksum;
	size16 urgent_pointer;
	size8 *options;
};

//nag_udp 8 B
struct nag_udp{
	size16 source_port;
	size16 destination_port;
	size16 length;
	size16 checksum;
};

//nag_icmp 8 B
struct nag_icmp{
	size8 type;
	size8 code;
	size16 checksum;
};

/*
 * ponizej sa struktury do przechowywania calych pakietow
 * zalozylem ze pakiety przekazane do zbadania nie zawieraja pola CRC
 */


struct dat_eth_dane {
	struct nag_ethernet *nag_eth;
	size8 *data;
};

struct dat_eth_ip_dane{
	struct nag_ethernet *nag_eth;
	struct nag_ip *nag_ip;
	size8 *data;
};

struct dat_eth_arp{
	struct nag_ethernet *nag_eth;
	struct nag_arp *nag_arp;
	size8 *data;

};

struct dat_eth_ip_icmp{
	struct nag_ethernet *nag_eth;
	struct nag_ip *nag_ip;
	struct nag_icmp *nag_icmp;
	size8 *data;

};

struct dat_eth_ip_udp{
	struct nag_ethernet *nag_eth;
	struct nag_ip *nag_ip;
	struct nag_udp *nag_udp;
	size8 *data;
};

struct dat_eth_ip_tcp{
	struct nag_ethernet *nag_eth;
	struct nag_ip *nag_ip;
	struct nag_tcp *nag_tcp;
	size8 *data;
};

/*
 * prototypy funkcji
 */

void *szereguj_dane(struct list *);
void zamien_mac_adresy(void *);
void skopiuj_eth_arp_do_bufora(void* buffor, struct dat_eth_arp *pakiet, size16 rozmiar);
void skopiuj_eth_ip_icmp_do_bufora(void *buffor, struct dat_eth_ip_icmp *pakiet, size16 rozmiar);
void dodaj_do_listy(struct list *list, union pakiet *pakiet, size16 rozmiar);
void zwolnij_pamiec(struct list *list);

char *icmp_type(size8); //funkcja wypisujaca znaczenie pola typ naglowka icmp
char *icmp_code(size8, size8); //funkcja wypisujaca znaczenie pola code przy danej wartości pola type naglowka icmp
void obsluga_eth_arp(struct dat_eth_arp *, size8 *, int); //funkcja kopiująca dane z buffora do strucktury pakietu eth/arp
void obsluga_eth_ip_icmp(struct dat_eth_ip_icmp *, size8 *, int);//funkcja kopiująca dane z buffora do strucktury pakietu eth/ip/icmp
void obsluga_eth_ip_tcp(struct dat_eth_ip_tcp *, size8 *, int);//funkcja kopiująca dane z buffora do strucktury pakietu eth/ip/tcp
void obsluga_eth_ip_udp(struct dat_eth_ip_udp *dat, size8 *pakiet, int);//funkcja kopiująca dane z buffora do strucktury pakietu eth/ip/udp
void obsluga_eth_ip_dane(struct dat_eth_ip_dane *, size8 *,int);//funkcja kopiująca dane z buffora do strucktury pakietu eth/dane
void obsluga_eth_dane(struct dat_eth_dane *dat, size8 *pakiet, int rozmiar);//przyporządkowuje dane do odpowiednjej struktury
void skopiuj_eth_dane_do_bufora(void* buffor, struct dat_eth_dane *pakiet, size16 rozmiar);
void skopiuj_eth_arp_do_bufora(void* buffor, struct dat_eth_arp *pakiet, size16 rozmiar);
void skopiuj_eth_ip_icmp_do_bufora(void *buffor, struct dat_eth_ip_icmp *pakiet, size16 rozmiar);
void skopiuj_eth_ip_udp_do_bufora(void *buffor, struct dat_eth_ip_udp *pakiet, size16 rozmiar);
void skopiuj_eth_ip_tcp_do_bufora(void *buffor, struct dat_eth_ip_tcp *pakiet, size16 rozmiar);
void skopiuj_eth_ip_dane_do_bufora(void *buffor, struct dat_eth_ip_dane *pakiet, size16 rozmiar);
void wypisz_nag_ethernet(struct nag_ethernet *);//funkcja wyświetlająca dane ze strucutury naglowka ethernet
void wypisz_nag_arp(struct nag_arp *);//funkcja wyświetlająca dane ze strucutury naglowka arp
void wypisz_nag_ip(struct nag_ip *);//funkcja wyświetlająca dane ze strucutury naglowka ip
void wypisz_nag_tcp(struct nag_tcp *);//funkcja wyświetlająca dane ze strucutury naglowka tcp
void wypisz_nag_udp(struct nag_udp *);//funkcja wyświetlająca dane ze strucutury naglowka udp
void wypisz_nag_icmp(struct nag_icmp *);//funkcja wyświetlająca dane ze strucutury naglowka icmp
void wypisz_dat_eth_arp(struct dat_eth_arp *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/arp
void wypisz_dat_eth_ip_tcp(struct dat_eth_ip_tcp *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
void wypisz_dat_eth_ip_udp(struct dat_eth_ip_udp *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
void wypisz_dat_eth_ip_icmp(struct dat_eth_ip_icmp *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
void wypisz_dat_eth_ip_dane(struct dat_eth_ip_dane *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
void wypisz_dat_eth_dane(struct dat_eth_dane *, int);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
void wypisz_opcje_tcp(size8 *, int); //wypisuje opcje znajdujące się w naglowku tcp
void wypisz_dane_icmp(size8 *, size8,  int);//wypisuje pole danych pakietu icmp
void free_eth_arp(struct dat_eth_arp *dat);//zwalnia pamięć
void free_eth_ip_tcp(struct dat_eth_ip_tcp *dat);
void free_eth_ip_udp(struct dat_eth_ip_udp *dat);
void free_eth_ip_icmp(struct dat_eth_ip_icmp *dat);
void free_eth_dane(struct dat_eth_dane *dat);
void free_eth_ip_dane(struct dat_eth_ip_dane *dat);
unsigned int scal_liczbe(size8 *, int , int ); // scala maksymalnie 4 jednobajtowe pola tablicy w jedną 4 bajtową liczbę

#ifdef __LITTLE_ENDIAN //sparwdzenie czy porzadku bajtowego. jesli littleendian to ponizsze funkcje przestawia bajty
	size16 swap2bytes(size16 a); //zamiana kolejności bajtów
	size32 swap4bytes(size32 a); // zmienia kolejność bajtów
	void bytes_swap_eth_arp(struct dat_eth_arp *);// funkcja wykonująca wszystkie potrzebne zamiany kolejności w pakitecie eth/arp
	void bytes_swap_eth_ip_udp(struct dat_eth_ip_udp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w pakiecie eth/ip/udp
	void bytes_swap_eth_ip_tcp(struct dat_eth_ip_tcp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w pakiecie eth/ip/tcp
	void bytes_swap_eth_ip_icmp(struct dat_eth_ip_icmp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w pakiecie eth/ip/icmp
	void bytes_swap_eth_ip_data(struct dat_eth_ip_dane *dat);
	void swap_nag_ip(struct nag_ip *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w nagłówku ip
	void swap_nag_udp(struct nag_udp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w nagłówku udp
	void swap_nag_tcp(struct nag_tcp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w nagłówku tcp
	void swap_nag_icmp(struct nag_icmp *);//funkcja wykonująca potrzebne zamianay kolenjości bajtów w nagłówku icmp
#endif
