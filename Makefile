all: airodump

airodump: main.o
	g++ -o airodump main.o -lpcap

main.o: main.cpp 

clean:
	rm -f airodump
	rm -f *.o

