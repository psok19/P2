	#include "naglowki.h"

	#define PROTOCOL_POSITION 9 //index pola position ramki IP w polu danych ramki ethernet
	#define ILOSC 10

int main(void) {

	struct list *list_eth_dat = malloc(sizeof(struct list));
	list_eth_dat->eth_type = NULL;
	list_eth_dat->ip_protocol = NULL;
	struct list *list_eth_arp = malloc(sizeof(struct list));
	list_eth_arp->eth_type = 0x806;
	list_eth_arp->ip_protocol = NULL;
	struct list *list_eth_ip_data = malloc(sizeof(struct list));
	list_eth_ip_data->eth_type = 0x800;
	list_eth_ip_data->ip_protocol = NULL;
	struct list *list_eth_ip_icmp = malloc(sizeof(struct list));
	list_eth_ip_icmp->eth_type = 0x800;
	list_eth_ip_icmp->ip_protocol = 1;
	struct list *list_eth_ip_tcp = malloc(sizeof(struct list));
	list_eth_ip_tcp->eth_type = 0x800;
	list_eth_ip_tcp->ip_protocol = 6;
	struct list *list_eth_ip_udp = malloc(sizeof(struct list));
	list_eth_ip_udp->eth_type = 0x800;
	list_eth_ip_udp->ip_protocol = 0x11;


//	puts("Lab_0"); /* prints Lab_0 */

	//definicja zmiennych
	int s; /*deskryptor gniazda*/
	int i = 0;
	int length = 0;

	//bufor dla ramek z Ethernetu
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	//wskaznik do naglowka Eth
	//unsigned char* etherhead = buffer;
	//wskaznik do miejsca rozpoczecia danych
	//unsigned char* data = buffer + 14;

//	printf("Program do odbierania ramek Ethernet z NIC!\n");

	//otworz gniazdo
	s = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (s == -1) {printf ("Nie moge otworzyc gniazda\n");}

	while (i<ILOSC) {

		//odbierz ramke Eth
		length = recvfrom(s, buffer, ETH_FRAME_LEN, 0, NULL, NULL);
		if (length == -1)
			printf ("Problem z odbiorem ramki \n");
		else {
			i++;
			printf ("Ramka: %d, dlugosc: %d [B]\n", i, length);
		}

		#if 0
		//wypisz zawartosc bufora
			for (j=0;j<length; j++) {
				printf ("%02x ", *(etherhead+j));
			}
			printf ("\n\n");
		#endif

		struct nag_ethernet nag_eth;
		memcpy(&nag_eth, buffer, ETHERNET_HEADER_LENGTH);

		if(__LITTLE_ENDIAN)
			nag_eth.type = swap2bytes(nag_eth.type);

		union pakiet *pakiet = malloc(sizeof(union pakiet));

		if(nag_eth.type == 0x0806){
			pakiet->eth_arp= malloc(sizeof(struct dat_eth_arp));
			obsluga_eth_arp(pakiet->eth_arp, buffer, length);
			wypisz_dat_eth_arp(pakiet->eth_arp, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/arp
			dodaj_do_listy(list_eth_arp, pakiet, length);
		}
		else if(nag_eth.type == 0x0800){ //jesli true to w polu danych ethernet jest ramka IP
			struct nag_ip nag_ip;
			memcpy(&nag_ip, buffer + ETHERNET_HEADER_LENGTH, IP_HEADER_MIN_LENGTH);

			if(nag_ip.protocol == 0x06) {// sprawdzenie czy protokol warstwy wyzsze to tcp
				pakiet->tcp = malloc(sizeof(struct dat_eth_ip_tcp));
				obsluga_eth_ip_tcp(pakiet->tcp, buffer, length);
				wypisz_dat_eth_ip_tcp(pakiet->tcp, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
				dodaj_do_listy(list_eth_ip_tcp, pakiet, length);
			}
			else if(nag_ip.protocol  == 0x11){//sprawdzenie czy udp
				pakiet->udp = malloc(sizeof(struct dat_eth_ip_udp));
				obsluga_eth_ip_udp(pakiet->udp, buffer,length);
				wypisz_dat_eth_ip_udp(pakiet->udp, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
				dodaj_do_listy(list_eth_ip_udp, pakiet,length);
			}
			else
			if(nag_ip.protocol  == 0x01){//sprawdzenie czy icmp
				pakiet->icmp = malloc(sizeof(struct dat_eth_ip_icmp));
				obsluga_eth_ip_icmp(pakiet->icmp, buffer, length);
				wypisz_dat_eth_ip_icmp(pakiet->icmp, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
				dodaj_do_listy(list_eth_ip_icmp,pakiet,length);
			}
			else{
				printf("NIEZNANY PROTOKOL W POLU DANYCH RAMKI IP\n");
				pakiet->ip_dane = malloc(sizeof(struct dat_eth_ip_dane));
				obsluga_eth_ip_dane(pakiet->ip_dane, buffer, length);
				wypisz_dat_eth_ip_dane(pakiet->ip_dane, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
				dodaj_do_listy(list_eth_ip_data, pakiet, length);
			}
		}
		else{
			printf("NIEZNANY PROTOKOL W POLU DANYCH RAMKI ETHERNET\n");
			pakiet->eth_dane = malloc(sizeof(struct dat_eth_dane));
			obsluga_eth_dane(pakiet->eth_dane, buffer, length);
			wypisz_dat_eth_dane(pakiet->eth_dane, length);//funkcja wyświetlająca dane ze strucutury pakietu eth/ip/tcp
			dodaj_do_listy(list_eth_dat, pakiet, length);
		}

	}
	free(buffer);

	//wyswietlanie i wysylanie
//
//	int i;
//					for(i = 0; i < rozmiar; i++)
//						printf("%.2x ", *((size8 *)buffer + i));

	//definicja zmiennych
		int s_out; /*deskryptor gniazda*/

		//bufor dla ramek z Ethernetu
		buffer = (void*)malloc(ETH_FRAME_LEN);
		//adres docelowy
		struct sockaddr_ll socket_address;
		int send_result = 0;
		struct ifreq ifr;
		int ifindex = 0;





		//dlugosc adresu Eth
		socket_address.sll_halen    = ETH_ALEN;

		//**************************wyslij ramke***********************************
		#if 1 //tu mozna zablokowac wysylanie

		size16 rozmiar;
		    printf("WYSYLANIE PAKIETOW ETH/ARP\n");
		    while(list_eth_arp->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;
		    	buffer = pobierz_dane(list_eth_arp, &rozmiar);
		    	send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
		    	if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
		    	close(s_out);
		    }
		    printf("WYSYLANIE PAKIETOW ETH/DANE\n");
		    while(list_eth_dat->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;

				buffer = pobierz_dane(list_eth_dat, &rozmiar);
				send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
				if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
				close(s_out);
		    }
		    printf("WYSYLANIE PAKIETOW IP/DANE\n");
		    while(list_eth_ip_data->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;

		    	buffer = pobierz_dane(list_eth_ip_data, &rozmiar);
				send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
				if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
				close(s_out);
			}
		    printf("WYSYLANIE PAKIETOW IP/ICMP\n");
		    while(list_eth_ip_icmp->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;

				buffer = pobierz_dane(list_eth_ip_icmp, &rozmiar);
				send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
				if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
				close(s_out);
		    }
		    printf("WYSYLANIE PAKIETOW IP/TCP\n");
		    while(list_eth_ip_tcp->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;

				buffer = pobierz_dane(list_eth_ip_tcp, &rozmiar);
				send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
				if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
				close(s_out);
		    }
		    printf("WYSYLANIE PAKIETOW IP/UDP\n");
		    while(list_eth_ip_udp->pierwszy != NULL){
		    	s_out = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
		    				if (s_out == -1) {printf ("Nie moge otworzyc gniazda s_out\n");}

		    			    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ);
		    			    if (ioctl(s_out, SIOCGIFINDEX, &ifr) == -1) {
		    			        perror("SIOCGIFINDEX");
		    			        exit(1);
		    			    }
		    			    ifindex = ifr.ifr_ifindex;
		    	//		    printf("Pobrano indeks karty NIC: %i\n", ifindex);
		    			    //usatwiono index urzadzenia siecowego
		    			    socket_address.sll_ifindex  = ifindex;

				buffer = pobierz_dane(list_eth_ip_udp, &rozmiar);
				send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
				if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}
				close(s_out);
		    }


			//=======wypisz zawartosc bufora do wyslania===========
			#if 0
				printf ("Dane do wyslania: \n");
				for (j=0;j<send_result; j++) {
					printf ("%02x ", *(etherhead+j));
				}
				printf ("\n");
			#endif
			//========koniec wypisywania===========================

		#endif //konic blokady wysylania
		//*******************************************************************************


	free(buffer);
	return EXIT_SUCCESS;
}
