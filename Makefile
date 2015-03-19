all:pktred

pktred:pktred.c
	gcc pktred.c -o pktred -lpfring -lnuma -lpcap -g
