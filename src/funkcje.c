#include "naglowki.h"

void wyslij_dane(void * buffer, int rozmiar){

		//definicja zmiennych
		int s_out; /*deskryptor gniazda*/
		int j;

		//bufor dla ramek z Ethernetu
//		void* buffer = (void*)malloc(ETH_FRAME_LEN);
		//wskaxnik do naglowka Eth
		unsigned char* etherhead = buffer;
		//wskaznik do miejsca rozpoczecia danych
		unsigned char* data = buffer + 14;

		//inny wskaznik do naglowka Eth
		struct ethhdr *eh = (struct ethhdr *)etherhead;
		//adres docelowy
		struct sockaddr_ll socket_address;
		int send_result = 0;
		struct ifreq ifr;
		int ifindex = 0;






		//przygotowanie danych do wyslania
		/*socket_address.sll_family   = PF_PACKET;
		//numer protokolu warstwy wyzszej <w tej chwili dowolny>
		socket_address.sll_protocol = htons(ETH_P_IP);
		//index urzadzenia siecowego pobrany dalej
		//socket_address.sll_ifindex  = 2;
		//protokol warswy wyzszej
		//socket_address.sll_hatype   = 0x0800; //IP
		//celem jest inny host
		socket_address.sll_pkttype  = PACKET_OTHERHOST; */
		//dlugosc adresu Eth
		socket_address.sll_halen    = ETH_ALEN;
		//MAC - poczatek
		/*socket_address.sll_addr[0]  = 0x00;
		socket_address.sll_addr[1]  = 0xaa;
		socket_address.sll_addr[2]  = 0xbb;
		socket_address.sll_addr[3]  = 0xcc;
		socket_address.sll_addr[4]  = 0xdd;
		socket_address.sll_addr[5]  = 0xee;*/
		//MAC - koniec
		//socket_address.sll_addr[6]  = 0x00;/*nie uzywane*/
		//socket_address.sll_addr[7]  = 0x00;/*nie uzywane*/


		///////////////////Ustaw naglowek ramki///////////////////////////////////////
		//Adres zrodlowy Eth
		unsigned char src_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
		//Adres docelowy Eth
		unsigned char dest_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
		memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
		memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
//		eh->h_proto = htons (0x0800); //Protokol warstwy wyzszej: 0x0800 - pakiet IPv4
		//////////////////////////////////////////////////////////////////////////////

//		/////////////////wylosuj lub ustaw dane dane do pola danych///////////////////////////////
//		//UWAGA! BUFOR DANYCH RAMKI JEST NASTEPUJACY: data[]
//		for (j = 0; j < 1500; j++) {
//			//data[j] = (unsigned char)((int) (255.0*rand()/(RAND_MAX+1.0)));
//			data[j] = 0xaa;
//			}
//		////////////////////////////////////////////////////////////////////////////

		//**************************wyslij ramke***********************************
		#if 1 //tu mozna zablokowac wysylanie
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


			send_result = sendto(s_out, buffer, rozmiar, 0,(struct sockaddr*)&socket_address, sizeof(socket_address));
			if (send_result == -1) { printf ("Nie moge wyslac danych! \n"); } //else { printf ("Wyslalem dane do intefejsu: %s \n", INTERFACE);}

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
				close(s_out);
}


/*
 * funkcje do obsługi listy
 */
//pakiet to wskaźnik na zaalokowaną dla pakietu pamięć
void dodaj_do_listy(struct list *list, union pakiet *pakiet, size16 rozmiar){
	if(list->pierwszy == NULL){//true => lista jest pusta
		struct list_item *item = malloc(sizeof(struct list_item));
		item->pakiet= pakiet;
		item->rozmiar = rozmiar;
		item->poprzedni = list->ostatni;
		item->nastepny = NULL;
		list->pierwszy = item;
		list->ostatni = list->pierwszy;
	}
	else{
		struct list_item *item = malloc(sizeof(struct list_item));
		item->pakiet= pakiet;
		item->rozmiar = rozmiar;
		item->poprzedni = list->ostatni;
		item->nastepny = NULL;
		list->ostatni->nastepny = item;
		list->ostatni = item;
	}
}

/*
 * funkcja zwraca wskaźnik na bufor danych do wysyłki
 */

void *pobierz_dane(struct list *list, size16 *rozmiar){
	void *buffor; //przechowuje adres danych przygotowanych do wysłania
	if (list->pierwszy == NULL){
		printf("error:lista jest pusta\n");
	}
	else if(list->pierwszy != NULL){//lista ma więcej niż jeden element
		buffor = szereguj_dane(list);
		*rozmiar = list->pierwszy->rozmiar;
		zwolnij_pamiec(list);
	}
	return buffor;
}

//zwraca wskaźnik na dane do wysłania
//void *szereguj_dane(struct list *list){
void *szereguj_dane(struct list *list){
	void *buffor = malloc(list->pierwszy->rozmiar);


	if(list->eth_type == 0x0806)//pakiet arp //odwrócić
		skopiuj_eth_arp_do_bufora(buffor, list->pierwszy->pakiet->eth_arp, list->pierwszy->rozmiar);
	else if(list->eth_type == 0x800){
		if(list->ip_protocol == 1){
			skopiuj_eth_ip_icmp_do_bufora(buffor, list->pierwszy->pakiet->icmp, list->pierwszy->rozmiar);
		}
		else if(list->ip_protocol == 0x11){
			skopiuj_eth_ip_udp_do_bufora(buffor, list->pierwszy->pakiet->udp, list->pierwszy->rozmiar);
		}
		else if(list->ip_protocol == 6){
			skopiuj_eth_ip_tcp_do_bufora(buffor, list->pierwszy->pakiet->tcp, list->pierwszy->rozmiar);
		}
		else{
			skopiuj_eth_ip_dane_do_bufora(buffor, list->pierwszy->pakiet->ip_dane, list->pierwszy->rozmiar);
		}
	}
	else{
		skopiuj_eth_dane_do_bufora(buffor, list->pierwszy->pakiet->eth_dane, list->pierwszy->rozmiar);
	}

	zamien_mac_adresy(buffor);

	return buffor;

}

void skopiuj_eth_dane_do_bufora(void* buffor, struct dat_eth_dane *pakiet, size16 rozmiar){
	if(__LITTLE_ENDIAN)
		pakiet->nag_eth->type = swap2bytes(pakiet->nag_eth->type);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano, pakiet->data, rozmiar - skopiowano);
}

void skopiuj_eth_arp_do_bufora(void* buffor, struct dat_eth_arp *pakiet, size16 rozmiar){
	if(__LITTLE_ENDIAN)
				bytes_swap_eth_arp(pakiet);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano, pakiet->nag_arp, ARP_HEADER_LENGTH);
	skopiowano+=ARP_HEADER_LENGTH;

	memcpy(buffor + skopiowano, pakiet->data, rozmiar - skopiowano);
}

void skopiuj_eth_ip_icmp_do_bufora(void *buffor, struct dat_eth_ip_icmp *pakiet, size16 rozmiar){
	if(__LITTLE_ENDIAN)
		bytes_swap_eth_ip_icmp(pakiet);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->nag_ip, IP_HEADER_MIN_LENGTH);
	skopiowano+=IP_HEADER_MIN_LENGTH;

	if(pakiet->nag_ip->IHL > 5){//są opcje IP
		int options_size = (pakiet->nag_ip->IHL - 5) * 4;
		memcpy(buffor + skopiowano,  pakiet->nag_ip->options, options_size);
		skopiowano+=options_size;
	}

	memcpy(buffor + skopiowano,  pakiet->nag_icmp, ICMP_HEADER_LENGTH);
	skopiowano+=ICMP_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->data, rozmiar - skopiowano);
}

void skopiuj_eth_ip_udp_do_bufora(void *buffor, struct dat_eth_ip_udp *pakiet, size16 rozmiar){
	if(__LITTLE_ENDIAN)
		bytes_swap_eth_ip_udp(pakiet);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->nag_ip, IP_HEADER_MIN_LENGTH);
	skopiowano+=IP_HEADER_MIN_LENGTH;

	if(pakiet->nag_ip->IHL > 5){//są opcje IP
		int options_size = (pakiet->nag_ip->IHL - 5) * 4;
		memcpy(buffor + skopiowano,  pakiet->nag_ip->options, options_size);
		skopiowano+=options_size;
	}

	memcpy(buffor + skopiowano, pakiet->nag_udp, UDP_HEADER_LENGTH);
	skopiowano += UDP_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->data, rozmiar - skopiowano);
}

void skopiuj_eth_ip_tcp_do_bufora(void *buffor, struct dat_eth_ip_tcp *pakiet, size16 rozmiar){
	if(__LITTLE_ENDIAN)
		bytes_swap_eth_ip_tcp(pakiet);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->nag_ip, IP_HEADER_MIN_LENGTH);
	skopiowano+=IP_HEADER_MIN_LENGTH;

	if(pakiet->nag_ip->IHL > 5){//są opcje IP
		int options_size = (pakiet->nag_ip->IHL - 5) * 4;
		memcpy(buffor + skopiowano,  pakiet->nag_ip->options, options_size);
		skopiowano+=options_size;
	}

	memcpy(buffor + skopiowano, pakiet->nag_tcp, TCP_HEADER_MIN_LENGTH);
	skopiowano += TCP_HEADER_MIN_LENGTH;

	if(pakiet->nag_tcp->data_offset > 5){
		int options_size =(pakiet->nag_tcp->data_offset - 5) * 4;
		memcpy(buffor + skopiowano, pakiet->nag_tcp->options, options_size);
		skopiowano += options_size;
	}

	memcpy(buffor + skopiowano,  pakiet->data, rozmiar - skopiowano);
}

void skopiuj_eth_ip_dane_do_bufora(void *buffor, struct dat_eth_ip_dane *pakiet, size16 rozmiar){
	if (__LITTLE_ENDIAN)
		bytes_swap_eth_ip_data(pakiet);

	int skopiowano = 0;

	memcpy(buffor + skopiowano,  pakiet->nag_eth, ETHERNET_HEADER_LENGTH);
	skopiowano+=ETHERNET_HEADER_LENGTH;

	memcpy(buffor + skopiowano,  pakiet->nag_ip, IP_HEADER_MIN_LENGTH);
	skopiowano+=IP_HEADER_MIN_LENGTH;

	if(pakiet->nag_ip->IHL > 5){//są opcje IP
		int options_size = (pakiet->nag_ip->IHL - 5) * 4;
		memcpy(buffor + skopiowano,  pakiet->nag_ip->options, options_size);
		skopiowano+=options_size;
	}

	memcpy(buffor + skopiowano,  pakiet->data, rozmiar - skopiowano);
}

void zwolnij_pamiec(struct list *list){
	struct list_item *do_zwolnienia;
	if(list->pierwszy != list->ostatni){
		do_zwolnienia = list->pierwszy;
		list->pierwszy = list->pierwszy->nastepny;//jesli w liscie jest tylko jeden element to przypisze NULL. jesli jest wiecej elementow przypisze adres nastepnego elemetnu
		list->pierwszy->poprzedni = NULL;
	}
	else if(list->pierwszy == list->ostatni){
		do_zwolnienia = list->pierwszy;
			list->pierwszy = NULL;//jesli w liscie jest tylko jeden element to przypisze NULL. jesli jest wiecej elementow przypisze adres nastepnego elemetnu
			list->ostatni = NULL;
	}

	if(list->eth_type == 0x0806){
		free_eth_arp(do_zwolnienia->pakiet->eth_arp);//zwalnia pamiec po pakiecie
		free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
		free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
	}
	else if(list->eth_type == 0x800){
		if(list->ip_protocol == 1){
			free_eth_ip_icmp(do_zwolnienia->pakiet->icmp);//zwalnia pamiec po pakiecie
			free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
			free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
		}
		else if(list->ip_protocol == 0x11){
			free_eth_ip_udp(do_zwolnienia->pakiet->udp);//zwalnia pamiec po pakiecie
			free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
			free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
		}
		else if(list->ip_protocol == 0x6){
			free_eth_ip_tcp(do_zwolnienia->pakiet->tcp);
			free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
			free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
		}
		else{
			free_eth_ip_dane(do_zwolnienia->pakiet->ip_dane);
			free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
			free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
		}
	}
	else{
		free_eth_dane(do_zwolnienia->pakiet->eth_dane);
		free(do_zwolnienia->pakiet);//zwalnia pamieć po unii pakiet
		free(do_zwolnienia);// zwalnia pamiec po strukturze list_item
	}
}

void zamien_mac_adresy(void *pakiet){

//	Adres docelowy Eth
			unsigned char dest_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

	void *a = malloc(MAC_ADDRESS_SIZE);
	memcpy(a, pakiet,MAC_ADDRESS_SIZE);

	memcpy(pakiet, dest_mac, MAC_ADDRESS_SIZE);
//	memcpy(pakiet, pakiet + MAC_ADDRESS_SIZE, MAC_ADDRESS_SIZE);

	memcpy(pakiet + MAC_ADDRESS_SIZE, a, MAC_ADDRESS_SIZE);


}

/*
 * funkcje dokonuje przyprządkowania danych ze strigna do odpoiednich struktu
 */


void obsluga_eth_dane(struct dat_eth_dane *dat, size8 *pakiet, int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if(__LITTLE_ENDIAN)
		dat->nag_eth->type = swap2bytes(dat->nag_eth->type);

}

void obsluga_eth_ip_dane(struct dat_eth_ip_dane *dat, size8 *pakiet,int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->nag_ip = malloc(IP_HEADER_MIN_LENGTH + sizeof(size8 *));
	memcpy(dat->nag_ip, pakiet + skopiowano, IP_HEADER_MIN_LENGTH);
	skopiowano += IP_HEADER_MIN_LENGTH;

	if(dat->nag_ip->IHL > 5){ // jeśli większe 5 to nag ip zawiera opcje
		int rozmiar_opcji = dat->nag_ip->IHL * 4 - IP_HEADER_MIN_LENGTH; //rozmiar opcji w bajtach
		dat->nag_ip->options = malloc(rozmiar_opcji);
		memcpy(dat->nag_ip->options, pakiet + skopiowano, rozmiar_opcji);
		skopiowano += rozmiar_opcji;
	}
	else
		dat->nag_ip->options = NULL;


	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if(__LITTLE_ENDIAN)
		bytes_swap_eth_ip_data(dat);
}

void obsluga_eth_arp(struct dat_eth_arp *dat, size8 *pakiet, int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->nag_arp = malloc(ARP_HEADER_LENGTH);
	memcpy(dat->nag_arp, pakiet + skopiowano, ARP_HEADER_LENGTH);
	skopiowano += ARP_HEADER_LENGTH;

	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if (__LITTLE_ENDIAN)
		bytes_swap_eth_arp(dat);
}


void obsluga_eth_ip_icmp(struct dat_eth_ip_icmp *dat, size8 *pakiet, int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->nag_ip = malloc(IP_HEADER_MIN_LENGTH + sizeof(size8 *));
	memcpy(dat->nag_ip, pakiet + skopiowano, IP_HEADER_MIN_LENGTH);
	skopiowano += IP_HEADER_MIN_LENGTH;


	if(dat->nag_ip->IHL > 5){ // jeśli większe 5 to nag ip zawiera opcje
		int rozmiar_opcji = dat->nag_ip->IHL * 4 - IP_HEADER_MIN_LENGTH; //rozmiar opcji w bajtach
		dat->nag_ip->options = malloc(rozmiar_opcji);
		memcpy(dat->nag_ip->options, pakiet + skopiowano, rozmiar_opcji);
		skopiowano += rozmiar_opcji;
	}
	else
		dat->nag_ip->options = NULL;

	dat->nag_icmp = malloc(ICMP_HEADER_LENGTH);
	memcpy(dat->nag_icmp, pakiet + skopiowano, ICMP_HEADER_LENGTH);
	skopiowano += ICMP_HEADER_LENGTH;

	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if (__LITTLE_ENDIAN)
		bytes_swap_eth_ip_icmp(dat);
}

void obsluga_eth_ip_tcp(struct dat_eth_ip_tcp *dat, size8 *pakiet, int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->nag_ip = malloc(IP_HEADER_MIN_LENGTH + sizeof(size8 *));
	memcpy(dat->nag_ip, pakiet + skopiowano, IP_HEADER_MIN_LENGTH);
	skopiowano += IP_HEADER_MIN_LENGTH;


	if(dat->nag_ip->IHL > 5){ // jeśli większe 5 to nag ip zawiera opcje
		int rozmiar_opcji = dat->nag_ip->IHL * 4 - IP_HEADER_MIN_LENGTH; //rozmiar opcji w bajtach
		dat->nag_ip->options = malloc(rozmiar_opcji);
		memcpy(dat->nag_ip->options, pakiet + skopiowano, rozmiar_opcji);
		skopiowano += rozmiar_opcji;
	}
	else
		dat->nag_ip->options = NULL;

	dat->nag_tcp = malloc(TCP_HEADER_MIN_LENGTH + sizeof(size8 *));
	memcpy(dat->nag_tcp, pakiet + skopiowano, TCP_HEADER_MIN_LENGTH);
	skopiowano += TCP_HEADER_MIN_LENGTH;
	if(dat->nag_tcp->data_offset > 5){
		int rozmiar_opcji = dat->nag_tcp->data_offset * 4 - TCP_HEADER_MIN_LENGTH;
		dat->nag_tcp->options = malloc(rozmiar_opcji);
		memcpy(dat->nag_tcp->options , pakiet + skopiowano, rozmiar_opcji);
		skopiowano += rozmiar_opcji;
	}
	else
		dat->nag_tcp->options = NULL;

	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if (__LITTLE_ENDIAN)
		bytes_swap_eth_ip_tcp(dat);
}

void obsluga_eth_ip_udp(struct dat_eth_ip_udp *dat, size8 *pakiet, int rozmiar){
	int skopiowano = 0;

	dat->nag_eth = malloc(ETHERNET_HEADER_LENGTH);
	memcpy(dat->nag_eth, pakiet, ETHERNET_HEADER_LENGTH);
	skopiowano += ETHERNET_HEADER_LENGTH;

	dat->nag_ip = malloc(IP_HEADER_MIN_LENGTH + sizeof(size8 *));
	memcpy(dat->nag_ip, pakiet + skopiowano, IP_HEADER_MIN_LENGTH);
	skopiowano += IP_HEADER_MIN_LENGTH;


	if(dat->nag_ip->IHL > 5){ // jeśli większe 5 to nag ip zawiera opcje
		int rozmiar_opcji = dat->nag_ip->IHL * 4 - IP_HEADER_MIN_LENGTH; //rozmiar opcji w bajtach
		dat->nag_ip->options = malloc(rozmiar_opcji);
		memcpy(dat->nag_ip->options, pakiet + skopiowano, rozmiar_opcji);
		skopiowano += rozmiar_opcji;
	}
	else
		dat->nag_ip->options = NULL;

	dat->nag_udp = malloc(UDP_HEADER_LENGTH);
	memcpy(dat->nag_udp, pakiet + skopiowano, UDP_HEADER_LENGTH);
	skopiowano += UDP_HEADER_LENGTH;

	dat->data = malloc(rozmiar - skopiowano);
	memcpy(dat->data, pakiet + skopiowano, rozmiar - skopiowano);

	if (__LITTLE_ENDIAN)
		bytes_swap_eth_ip_udp(dat);
}

/*
 * funkcje wypisujace strukture naglowkow
 */
void wypisz_nag_ethernet(struct nag_ethernet *struktura){
	int i;
	printf("Ethernet header:\n");
	printf("\tDestination address: ");
	i = 0;
	printf("%.2x", struktura->destynation_address[i]);
	for(i = 1; i < 6; i++)
		printf(":%.2x", struktura->destynation_address[i]);
	printf("\n");
	i = 0;
	printf("\tSource address: ");
	printf("%.2x", struktura->source_address[i]);
		for(i = 1; i < 6; i++)
			printf(":%.2x", struktura->source_address[i]);
	printf("\n");
	printf("\tType: 0x%.4x(", struktura->type);
	if(struktura->type == 0x0800)
		printf("IP");
	else if(struktura->type == 0x0806)
		printf("ARP");
	else
		printf("unknown");
	printf(")\n");
}

void wypisz_nag_arp(struct nag_arp *structura){
	printf("ARP header:\n");
	printf("\tHardware type: 0x%.4x(", structura->hardware_type);
	if(structura->hardware_type == 1)
		printf("ethernet");
	else
		printf("unknown");
	printf(")\n");
	printf("\tProtocol type: 0x%.4x(", structura->protocol_type);
	if(structura->protocol_type == 0x0800)
		printf("IP");
	else
		printf("unknown");
	printf(")\n");
	printf("\tHardware addresses length: %u\n", structura->hardware_adresses_length);
	printf("\tProtocol addresses length: %u\n", structura->protocol_adresses_length);
	printf("\tOpcode: %u(", structura->opcode);
	if (structura->opcode == 1)
		printf("request");
	else if(structura->opcode == 2)
		printf("reply");
	printf(")\n");

}

void wypisz_nag_ip(struct nag_ip *nag){
	printf("IP header:\n");
	printf("\tVersion: %u\n", nag->version);
	printf("\tHeader length: %u bytes\n", nag->IHL * 4);
	printf("\tDSCP: 0x%.2x\n", nag->DSCP);
	printf("\tECN: 0x%.1x\n", nag->ECN);
	printf("\tTotal length: %u\n", nag->total_length);
	printf("\tIdentification: 0x%.4x\n", nag->identification);
	printf("\tFlags: \n");
	printf("\t\tReserved bit: %x\n", nag->reserved_bit);
	printf("\t\tDon't fragment: %x\n", nag->dont_fragment);
	printf("\t\tMore fragments: %x\n", nag->more_fragments);
	printf("\tFragmnet offset: %u\n", nag->fragmnet_offset);
	printf("\tTime to live: %u\n", nag->time_to_live);
	printf("\tProtocol: %u (", nag->protocol);
	if(nag->protocol == 1)
		printf("ICMP");
	else if(nag->protocol == 6)
		printf("TCP");
	else if(nag->protocol == 17)
		printf("UDP");
	else
		printf("unknown");
	printf(")\n");
	printf("\tHeader_checksum: 0x%.4x\n", nag->header_checksum);
	int i;
	printf("\tSource address: ");
	i = 0;
	printf("%u", nag->source_address[i]);
	for(i = 1; i < 4; i++)
		printf(".%u", nag->source_address[i]);
	printf("\n");
	printf("\tDestination address: ");
	i = 0;
	printf("%u", nag->destination_address[i]);
	for(i = 1; i < 4; i++)
		printf(".%u", nag->destination_address[i]);
	printf("\n");

	if(nag->IHL > 5){ // jeśli większe 5 to nag ip zawiera opcje
			int rozmiar_opcji = nag->IHL * 4 - IP_HEADER_MIN_LENGTH; //rozmiar opcji w bajtach
			printf("\tOptions:");int i;
			for(i = 0; i < rozmiar_opcji; i++)
				printf(" %.2x", nag->options[i]);
			printf("\n");
	}
}

void wypisz_nag_tcp(struct nag_tcp *nag){
	printf("TCP header:\n");
	printf("\tSource port: %u\n", nag->source_port);
	printf("\tDestination port: %u\n", nag->destination_port);
	printf("\tSequence_number: %u\n", nag->sequence_number);
	printf("\tAcknowledgment number: %u\n", nag->acknowledgment_number);
	printf("\tData offset: %u bytes\n", nag->data_offset * 4);
	printf("\treserved: %x\n", nag->reserved);
	printf("\tnonce: %x\n", nag->NS);
	printf("\tCWR: %x\n", nag->CWR);
	printf("\tECE: %x\n", nag-> ECE);
	printf("\tURG: %x\n", nag->URG);
	printf("\tACK: %x\n", nag->ACK);
	printf("\tPSH: %x\n", nag->PSH);
	printf("\tRST: %x\n", nag->RST);
	printf("\tSYN: %x\n", nag->SYN);
	printf("\tFIN: %x\n", nag->FIN);
	printf("\tWindow: %u\n", nag->window);
	printf("\tChecksum: 0x%.4x\n", nag->checksum);
	printf("\tUrgent pointer: %u\n", nag->urgent_pointer);
	wypisz_opcje_tcp(nag->options, nag->data_offset * 4 - TCP_HEADER_MIN_LENGTH);
}

void wypisz_nag_udp(struct nag_udp *nag){
	printf("UDP header:\n");
	printf("\tSource port: %u\n", nag->source_port);
	printf("\tDestination port: %u\n", nag->destination_port);
	printf("\tLength: %u\n", nag->length);
	printf("\tChecksum: 0x%.4x\n", nag->checksum);
}

void wypisz_nag_icmp(struct nag_icmp *nag){
	printf("ICMP header:\n");
	printf("\tType: %u(", nag->type);
	printf("%s",icmp_type(nag->type));
	printf(")\n");
	printf("\tCode: %u", nag->code);
	if(nag->type == 3 || nag->type == 5 || nag->type == 11 || nag->type== 12 || nag->type == 40)
		printf("(%s)", icmp_code(nag->type, nag->code));
	printf("\n");
	printf("\tChecksum: 0x%.4x\n", nag->checksum);
}

char *icmp_code(size8 t, size8 c){
	if(t == 3 && c == 0)
		return "Destination network unreachable";
	else if(t == 3 && c == 1)
		return "Destination host unreachable";
	else if(t == 3 && c == 2)
		return "Destination protocol unreachable";
	else if(t == 3 && c == 3)
		return "Destination port unreachable";
	else if(t == 3 && c == 4)
			return "Fragmentation required, and DF flag set";
	else if(t == 3 && c == 5)
			return "Source route failed";
	else if(t == 3 && c == 6)
			return "Destination network unknown";
	else if(t == 3 && c == 7)
			return "Destination host unknown";
	else if(t == 3 && c == 8)
			return "Source host isolated";
	else if(t == 3 && c == 9)
			return "Network administratively prohibited";
	else if(t == 3 && c == 10)
			return "Host administratively prohibited";
	else if(t == 3 && c == 11)
			return "Network unreachable for TOS";
	else if(t == 3 && c == 12)
			return "Host unreachable for TOS";
	else if(t == 3 && c == 13)
			return "Communication administratively prohibited";
	else if(t == 3 && c == 14)
			return "Host Precedence Violation";
	else if(t == 3 && c == 15)
			return "Precedence cutoff in effect";
	else if(t == 5 && c == 0)
			return "Redirect Datagram for the Network";
	else if(t == 5 && c == 1)
			return "Redirect Datagram for the Host";
	else if(t == 5 && c == 2)
			return "Redirect Datagram for the TOS & network";
	else if(t == 5 && c == 3)
			return "Redirect Datagram for the TOS & host";
	else if(t == 11 && c == 0)
			return "TTL expired in transit";
	else if(t == 11 && c == 1)
			return "Fragment reassembly time exceeded";
	else if(t == 12 && c == 0)
			return "Pointer indicates the error";
	else if(t == 12 && c == 1)
			return "Missing a required option";
	else if(t == 12 && c == 2)
			return "Bad length";
	else if(t == 40 && c == 0)
		return "Bad SPI";
	else if(t == 40 && c == 1)
		return "Authentication Failed";
	else if(t == 40 && c == 2)
		return "Decompression Failed";
	else if(t == 40 && c == 3)
		return "Decryption Failed";
	else if(t == 40 && c == 4)
		return "Need Authentication";
	else if(t == 40 && c == 5)
		return "Need Authorization";
	else
		return "unknown";
}

char *icmp_type(size8 v){
	switch(v){
	case 0:
		return "Echo reply";
	case 3:
			return "Destination Unreachable";
	case 5:
		return "Redirect Message";
	case 8:
		return "Echo request";
	case 9:
		return "Router Advertisement";
	case 10:
		return "Router Solicitation";
	case 11:
		return "Time Exceeded";
	case 12:
		return "Parameter Problem: Bad IP header";
	case 13:
		return "Timestamp";
	case 14:
		return "Timestamp Reply";
	case 18:
		return "Address Mask Reply";
	case 40:
		return "Photuris";
	default :
		return "unknown";
	}
}

void wypisz_dat_eth_dane(struct dat_eth_dane *dat, int rozmiar){
	printf("PACKET ETHERNET/DATA\n");
		wypisz_nag_ethernet(dat->nag_eth);
		int n; // n - indeks na cala tablice danych


		if(ETHERNET_HEADER_LENGTH < rozmiar){
			printf("\tData:");
			for( n = 0; n < rozmiar - ETHERNET_HEADER_LENGTH; n++){
				printf("%.2x ", *(dat->data + n));
			}
			printf("\n");
		}
		printf("\n\n");
}

void wypisz_dat_eth_arp(struct dat_eth_arp *dat, int rozmiar){
	printf("PACKET ETHERNET/ARP\n");
	wypisz_nag_ethernet(dat->nag_eth);
	wypisz_nag_arp(dat->nag_arp);


///////////////////////////////////////////////////////////////////////////////
	int i = 0; //indeks do wypisywania poszczegolnych adresow
		int n = 0;  // indeks na tablice dane
	printf("\tHardware address of sender: ");
	printf("%.2x", dat->data[n++]);
	i++;
	for(; i < dat->nag_arp->hardware_adresses_length; i++){
		printf(":%.2x", dat->data[n++]);
	}
	printf("\n");


	i = 0;
	printf("\tProtocol address of sender: ");
	printf("%u", dat->data[n++]);
	i++;
	for( ; i < dat->nag_arp->protocol_adresses_length; i++){
	printf(".%u", dat->data[n++]);
	}
	printf("\n");


	i = 0;
	printf("\tHardware address of target: ");
	printf("%.2x", dat->data[n++]);
	i++;
	for( ; i < dat->nag_arp->hardware_adresses_length; i++){
		printf(":%.2x", dat->data[n++]);
	}
	printf("\n");


	i = 0;
	printf("\tProtocol address of target: ");
	printf("%u", dat->data[n++]);
	i++;
	for( ; i < dat->nag_arp->protocol_adresses_length; i++){
		printf(".%u", dat->data[n++]);
	}
	printf("\n");


//////////////////////////////////////////////////////////////////////////////

	int data_size = rozmiar - n - ETHERNET_HEADER_LENGTH - ARP_HEADER_LENGTH;
	if(0 < data_size){
		printf("Data:\n");
		for(i = 0; i < data_size; i++, n++){
			printf("%.2x ", *(dat->data + n));
		}
		printf("\n");
	}
	printf("\n\n");
}

void wypisz_dat_eth_ip_dane(struct dat_eth_ip_dane *dat, int rozmiar){
	wypisz_nag_ethernet(dat->nag_eth);
	wypisz_nag_ip(dat->nag_ip);
	int rozmiar_danych = rozmiar - (ETHERNET_HEADER_LENGTH + dat->nag_ip->IHL * 4);
	if(rozmiar_danych > 0){
		printf("Data:\n");
		int i;
		for(i = 0; i < rozmiar_danych; i++)
			printf("%.2x ", dat->data[i]);
	}
	printf("\n\n\n");

}

void wypisz_dat_eth_ip_tcp(struct dat_eth_ip_tcp *dat, int rozmiar){
	printf("PACKET ETHERNET/IP/TCP\n");
	wypisz_nag_ethernet(dat->nag_eth);
	wypisz_nag_ip(dat->nag_ip);
	wypisz_nag_tcp(dat->nag_tcp);
	int n; //i- index do opcji , n - index do tablicy dane

	int data_size = rozmiar - ETHERNET_HEADER_LENGTH - dat->nag_ip->IHL * 4 - dat->nag_tcp->data_offset * 4;
	if(0 < data_size){
		printf("Data:\n");
		for(n=0 ; n < data_size; n++){
			printf("%.2x ", *(dat->data + n));
		}
		printf("\n");
	}
	printf("\n\n");
}

void wypisz_opcje_tcp(size8 *options, int opt_size){
	int i = 0;
	int length; //przechowuje wartosc pola length opcji
	if(0 < opt_size)
		printf("\tOptions:\n");
	while(i < opt_size){
		if(options[i] == 0){
			printf("\t\tEnd of options\n");
			i = opt_size;
		}
		else if(options[i] == 2){
			length = options[i+1];
			printf("\t\tMax segment size: %d bytes\n", (((size16)options[i+2]) << 8) | options[i+3]);
			i+=length;
		}
		else if(options[i] == 1){
			printf("\t\tNo operation\n");
			i++;
		}
		else if(options[i] == 3){
			length = options[i+1];
			printf("\t\tWindow Scale: %d\n", options[i+2]);
			i+=length;
		}
		else if(options[i] == 4){
			printf("\t\tSACK Permitted\n");
			i+=options[i+1];
		}
		else if(options[i] == 5){
			printf("\t\tSACK:");
			int n;
			for(n = 2; n < options[i + 1]; n++ )
				printf(" %.2x ", options[i + n]);
			printf("\n");
			i+=options[i+1];
		}
		else if(options[i] == 8){
			printf("\t\tTimestamps:\n");

			printf("\t\t\tTSval: %u\n", scal_liczbe(options,i+2, i+5));
			printf("\t\t\tTSecr: %u\n", scal_liczbe(options, i+ 6, i+ 9));
			i+=options[i+1];
		}
		else if(options[i] == 27){
			printf("\t\tQuick-Start Response:\n");
			printf("\t\t\tFunc: %u\n", options[i+2] >> 4);
			printf("\t\t\tRest Request: %u\n", options[i+2] & 0xf);
			printf("\t\t\tQS TTL: %u\n", options[i+3]);
			printf("\t\t\tQS Nonce: 0x%x\n", (((int)options[i + 4]) << 22 )| (((int)options[i + 5]) << 14 ) | (((int)options[i + 6]) << 6 )| (options[i+7] >> 2));
			printf("R: %u\n", options[i + 7] & 0x3);
			i+=options[i+1];
		}
		else if(options[i] == 28){
			printf("\t\tUser Timeout Option:\n");
			printf("\t\t\tGranularity: %u(", options[i+2] >> 7);
			if(options[i+2] >> 7 == 1)
				printf("minutes");
			else if(options[i+2] >> 7 == 0)
				printf("seconds");
			printf(")\n");
			printf("\t\t\tUser Timeout: %d\n", (((int)(options[i + 2] & 0x7f)) << 8) | ((int)options[i + 3]) );
			i+=options[i+1];
		}
		else if(options[i] == 29){
			printf("\t\tTCP Authentication Option:\n");
			printf("\t\t\tKeyID: %u\n", options[i+2]);
			printf("\t\t\tRNextKeyID: %d\n", options[i+3]);
			printf("\t\t\tMessage Authentication Code:");
			int n;
			for(n = 0; n < options[i+1] - 2; n++)
				printf(" %.2x", options[i + 2 + n]);
			printf("\n");
			i+=options[i+1];
		}

		else if(options[i] == 30){
			printf("\t\tMultipath TCP:\n");
			printf("\t\t\tSubtype: %u\n", options[i+2] >> 4);
			printf("\t\t\tSpecific data: %x", options[i+2] & 0xf);
			int n;
			for(n = 0; n < options[i+1] - 3; n++)
				printf(" %.2x", options[i + 3 + n]);
			printf("\n");
			i+=options[i+1];
		}
		else if(options[i] == 34){
			printf("\t\tTCP Fast Open Cookie:");
			int n;
			for(n = 0; n < options[i + 1] - 2; n++)
				printf(" %.2x", options[i + 2 + n]);
			printf("\n");
			i+=options[i+1];
		}
		else {
			printf("\t\tUnknown option %d\n", options[i]);
			i+=1;
		}

	}
}

void wypisz_dat_eth_ip_udp(struct dat_eth_ip_udp *dat, int rozmiar){
	printf("PACKET ETHERNET/IP/UDP\n");
	wypisz_nag_ethernet(dat->nag_eth);
	wypisz_nag_ip(dat->nag_ip);
	wypisz_nag_udp(dat->nag_udp);
	printf("Data:\n");
	int i;
	for(i = 0; i < rozmiar -  ETHERNET_HEADER_LENGTH - dat->nag_ip->IHL * 4 - UDP_HEADER_LENGTH ; i++){
		printf("%.2x ", *(dat->data + i));
	}
	printf("\n\n\n");
}

void wypisz_dat_eth_ip_icmp(struct dat_eth_ip_icmp *dat, int rozmiar){
	printf("PACKET ETHERNET/IP/ICMP\n");
	wypisz_nag_ethernet(dat->nag_eth);
	wypisz_nag_ip(dat->nag_ip);
	wypisz_nag_icmp(dat->nag_icmp);
	int data_size= rozmiar - ETHERNET_HEADER_LENGTH - dat->nag_ip->IHL * 4 - ICMP_HEADER_LENGTH;
	wypisz_dane_icmp(dat->data, dat->nag_icmp->type,  data_size);
	printf("\n\n\n");
}

void wypisz_dane_icmp(size8 *data, size8 type,  int data_size){

	if(type == 0 || type == 8){
		printf("\tIdentifier: %u\n", scal_liczbe(data, 0 , 1));
		printf("\tSequence Number: %u\n", scal_liczbe(data, 2 , 3));
		int i;
		printf("\tTimestamp: ");
		for(i = 4; i < 12; i++)
			printf(" %.2x", data[i]);
		printf("\n");
		printf("\tData: ");
		for( ; i < data_size; i++)
			printf(" %.2x", data[i]);
		printf("\n");
	}
	else if(type == 3 || type == 11){
		struct nag_ip nag_ip;
		memcpy(&nag_ip, data + 4   , IP_HEADER_MIN_LENGTH);
		if(__LITTLE_ENDIAN)
			swap_nag_ip(&nag_ip);
		wypisz_nag_ip(&nag_ip);
		int i;
		printf("\tData: ");
		for(i  = IP_HEADER_MIN_LENGTH + 4; i < data_size; i++)
			printf(" %.2x", data[i]);
		printf("\n");
	}
	else if(type == 12){
			printf("\tPointer: %u\n", data[0]);
			struct nag_ip nag_ip;
			memcpy(&nag_ip, data + 4, IP_HEADER_MIN_LENGTH);
			wypisz_nag_ip(&nag_ip);
			int i;
			printf("\tData: ");
			for(i  = IP_HEADER_MIN_LENGTH + 4; i < data_size; i++)
				printf(" %.2x", data[i]);
			printf("\n");
		}
	else if(type == 40){
		printf("\tReserved: %u\n", scal_liczbe(data, 0 ,1));
		printf("\tPointer: %u\n", scal_liczbe(data, 2 ,3));
		struct nag_ip nag_ip;
		memcpy(&nag_ip, data + 4, IP_HEADER_MIN_LENGTH);
		wypisz_nag_ip(&nag_ip);
		int i;
		printf("\tData: ");
		for(i  = IP_HEADER_MIN_LENGTH + 4; i < data_size; i++)
			printf(" %.2x", data[i]);
		printf("\n");
	}
	else if( type == 5){
		printf("\tGateway Internet Address: ");
		int i= 0;
		printf("%u", data[i++]);
		for(; i < 4; i++){
		printf(".%u", data[i]);
		}
		printf("\n");


		struct nag_ip nag_ip;
		memcpy(&nag_ip, data, IP_HEADER_MIN_LENGTH);
		i  += IP_HEADER_MIN_LENGTH;
		wypisz_nag_ip(&nag_ip);

		printf("\tData: ");
		for(; i < data_size; i++)
		printf(" %.2x", data[i]);
		printf("\n");
	}
	else if(type == 9){
		printf("Num Addrs: %u\n", data[0]);
		printf("Addr Entry Size: %u\n", data[1]);
		printf("LIfetime: %u\n", scal_liczbe(data, 2, 3));
		int x = 4; // indeks do tablicy data
		int i, n; // i - inex wpisów, n - index 4-bajtowych lini w jednym wpisie

		for(i = 0; i < data[0]; i++){
			printf("\tRouter address: %u", data[x++]);
			for(;x % 4;){
				printf(".%u", data[x++]);
			}
			printf("\n");
			for(n = 1; n < data[1]; n++){
				printf("\tPreference level: %d", (int)scal_liczbe(data, x, x + 3));
				x += 4;
			}

		}
	}
	else if(type == 13 || type == 14){
		printf("\tIdentifier: %u\n", scal_liczbe(data, 0 , 1));
		printf("\tSequence Number: %u\n", scal_liczbe(data, 2 , 3));
		printf("\tOriginate Timestamp: %u\n", scal_liczbe(data, 4, 7));
		printf("\tReceive Timestamp: %u\n", scal_liczbe(data, 8, 11));
		printf("\tTransmit Timestamp: %u\n", scal_liczbe(data, 12, 15));
	}
	else{
		printf("\tICMP Data:");
		int i;
		for(i = 0; i < data_size; i++){
			printf(" %.2x", *(data + i));
		}
	}
}
/*
 * funkcja scal_liczbe przekształca ciąg bajtów(max 4) w liczbę. poczatek i koniec to
 * indeksy pierwszego i ostatniego scalanego bajtu.
 */
unsigned int scal_liczbe(size8 *tab, int poczatek, int koniec){
	unsigned int a = 0;
	int i;
	for(i = poczatek; i <= koniec; i++){
		a = a << 8;
		a = a | tab[i];
	}
	return a;
}

/*
 * funkcje zwalniające pamięć
 */

void free_eth_arp(struct dat_eth_arp *dat){
	free(dat->nag_eth);
	free(dat->nag_arp);
	free(dat->data);
	free(dat);
}

void free_eth_ip_tcp(struct dat_eth_ip_tcp *dat){
	free(dat->nag_eth);
	free(dat->nag_ip->options);
	free(dat->nag_ip);
	free(dat->nag_tcp->options);
	free(dat->nag_tcp);
	free(dat->data);
	free(dat);
}

void free_eth_ip_udp(struct dat_eth_ip_udp *dat){
	free(dat->nag_eth);
	free(dat->nag_ip->options);
	free(dat->nag_ip);
	free(dat->nag_udp);
	free(dat->data);
	free(dat);
}

void free_eth_ip_icmp(struct dat_eth_ip_icmp *dat){
	free(dat->nag_eth);
	free(dat->nag_ip->options);
	free(dat->nag_ip);
	free(dat->nag_icmp);
	free(dat->data);
	free(dat);
}

void free_eth_ip_dane(struct dat_eth_ip_dane *dat){
	free(dat->nag_eth);
	free(dat->nag_ip->options);
	free(dat->nag_ip);
	free(dat->data);
	free(dat);
}

void free_eth_dane(struct dat_eth_dane *dat){
	free(dat->nag_eth);
	free(dat->data);
	free(dat);
}



#ifdef __LITTLE_ENDIAN
size16 swap2bytes(size16 a){
	return (a >> 8) | (a << 8);
}

size32 swap4bytes(size32 a){
	return (a << 24) | ((a << 8) & 0x00ff0000) | ((a >> 8) & 0x0000ff00) | (a >> 24);
}


void bytes_swap_eth_arp(struct dat_eth_arp *dat){
	dat->nag_eth->type = swap2bytes(dat->nag_eth->type);
	dat->nag_arp->hardware_type = swap2bytes(dat->nag_arp->hardware_type);
	dat->nag_arp->protocol_type = swap2bytes(dat->nag_arp->protocol_type);
	dat->nag_arp->opcode = swap2bytes(dat->nag_arp->opcode);
}

void bytes_swap_eth_ip_tcp(struct dat_eth_ip_tcp *dat){
	dat->nag_eth->type = swap2bytes(dat->nag_eth->type);
	swap_nag_ip(dat->nag_ip);
	swap_nag_tcp(dat->nag_tcp);
}

void bytes_swap_eth_ip_udp(struct dat_eth_ip_udp *dat){
	dat->nag_eth->type = swap2bytes(dat->nag_eth->type);
	swap_nag_ip(dat->nag_ip);
	swap_nag_udp(dat->nag_udp);
}

void bytes_swap_eth_ip_icmp(struct dat_eth_ip_icmp *dat){
	dat->nag_eth->type = swap2bytes(dat->nag_eth->type);
	swap_nag_ip(dat->nag_ip);
	swap_nag_icmp(dat->nag_icmp);
}

void bytes_swap_eth_ip_data(struct dat_eth_ip_dane *dat){
	dat->nag_eth->type = swap2bytes(dat->nag_eth->type);
	swap_nag_ip(dat->nag_ip);
}


void swap_nag_ip(struct nag_ip *dat){
	dat->total_length = swap2bytes(dat->total_length);
	dat->identification = swap2bytes(dat->identification);
	size16 * a = &dat->identification + 1;
	*a = swap2bytes(*a);

	dat->header_checksum= swap2bytes(dat->header_checksum);
}

void swap_nag_udp(struct nag_udp *dat){
	dat->checksum = swap2bytes(dat->checksum);
	dat->source_port = swap2bytes(dat->source_port);
	dat->length = swap2bytes(dat->length);
	dat->destination_port = swap2bytes(dat->destination_port);
}

void swap_nag_tcp(struct nag_tcp *nag){
	nag->source_port = swap2bytes(nag->source_port);
	nag->destination_port = swap2bytes(nag->destination_port);
	nag->sequence_number = swap4bytes(nag->sequence_number);
	nag->acknowledgment_number = swap4bytes(nag->acknowledgment_number);
	nag->window= swap2bytes(nag->window);
	nag->checksum = swap2bytes(nag->checksum);
	nag->urgent_pointer = swap2bytes(nag->urgent_pointer);
}

void swap_nag_icmp(struct nag_icmp *nag){
	nag->checksum = swap2bytes(nag->checksum);
}

#endif
