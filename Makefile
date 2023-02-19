CC=gcc

SERVER=server
SERVER_OBJ=server_ssl.o
CLIENT=client
CLIENT_OBJ=client_ssl.o

LIBS=-lssl -lcrypto
LDFLAGS=-Lopenssl/
INCLUDES=-Iopenssl/include/

all: $(CLIENT) $(SERVER)

$(CLIENT): $(CLIENT_OBJ)
	$(CC) $(CLIENT_OBJ) -o $(CLIENT) $(LDFLAGS) $(LIBS)


$(SERVER): $(SERVER_OBJ)
	$(CC) $(SERVER_OBJ) -o $(SERVER) $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(LIBS) $(LDFLAGS) $(INCLUDES) -c -o $@ $<


clean:
	rm -rf $(SERVER) $(SERVER_OBJ) $(CLIENT) $(CLIENT_OBJ)
