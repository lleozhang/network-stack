CC=g++
CFLAGS=-lpcap -lpthread -Wl,--wrap=socket -Wl,--wrap=bind -Wl,--wrap=listen -Wl,--wrap=read -Wl,--wrap=write -Wl,--wrap=connect -Wl,--wrap=accept -Wl,--wrap=close 
SRC_DIR=src
TAR_DIR=build
OPT_FLAG=-g -o 
all:$(TAR_DIR)/router $(TAR_DIR)/lossyrouter $(TAR_DIR)/client $(TAR_DIR)/server $(TAR_DIR)/echo_client $(TAR_DIR)/echo_server $(TAR_DIR)/perf_client $(TAR_DIR)/perf_server

$(TAR_DIR)/router:$(SRC_DIR)/server.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	mkdir $(TAR_DIR)
	$(CC) $(SRC_DIR)/server.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/router $(CFLAGS)

$(TAR_DIR)/echo_client:$(SRC_DIR)/echo_client.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/echo_client.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/echo_client $(CFLAGS)

$(TAR_DIR)/echo_server:$(SRC_DIR)/echo_server.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/echo_server.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/echo_server $(CFLAGS)
	
$(TAR_DIR)/perf_client:$(SRC_DIR)/perf_client.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/perf_client.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/perf_client $(CFLAGS)

$(TAR_DIR)/perf_server:$(SRC_DIR)/perf_server.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/perf_server.c $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/perf_server $(CFLAGS)

$(TAR_DIR)/lossyrouter:$(SRC_DIR)/cp8.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/lossyrouter.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/cp8.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/lossyrouter.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/lossyrouter $(CFLAGS)

$(TAR_DIR)/client:$(SRC_DIR)/client.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/client.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/client $(CFLAGS)
	
$(TAR_DIR)/server:$(SRC_DIR)/server.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/socket.o $(SRC_DIR)/router.o $(SRC_DIR)/unp.o
	$(CC) $(SRC_DIR)/serve.cpp $(SRC_DIR)/device.o $(SRC_DIR)/packetio.o $(SRC_DIR)/ip.o $(SRC_DIR)/router.o $(SRC_DIR)/socket.o $(SRC_DIR)/unp.o $(OPT_FLAG) $(TAR_DIR)/server $(CFLAGS)

$(SRC_DIR)/device.o:$(SRC_DIR)/device.cpp
	g++ -c $(SRC_DIR)/device.cpp
	mv device.o $(SRC_DIR)/ 

$(SRC_DIR)/packetio.o:$(SRC_DIR)/packetio.cpp
	g++ -c $(SRC_DIR)/packetio.cpp 
	mv packetio.o $(SRC_DIR)/

$(SRC_DIR)/ip.o:$(SRC_DIR)/ip.cpp
	g++ -c $(SRC_DIR)/ip.cpp
	mv ip.o $(SRC_DIR)/

$(SRC_DIR)/router.o:$(SRC_DIR)/router.cpp
	g++ -c $(SRC_DIR)/router.cpp 
	mv router.o $(SRC_DIR)/
	
$(SRC_DIR)/lossyrouter.o:$(SRC_DIR)/lossyrouter.cpp 
	g++ -c $(SRC_DIR)/lossyrouter.cpp
	mv lossyrouter.o $(SRC_DIR)/

$(SRC_DIR)/socket.o:$(SRC_DIR)/socket.cpp
	g++ -c $(SRC_DIR)/socket.cpp
	mv socket.o $(SRC_DIR)/
	
$(SRC_DIR)/unp.o:$(SRC_DIR)/unp.c
	g++ -c $(SRC_DIR)/unp.c
	mv unp.o $(SRC_DIR)/

clean:
	rm -r build
	rm $(SRC_DIR)/*.o
