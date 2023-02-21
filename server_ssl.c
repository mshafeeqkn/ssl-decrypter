#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define FAIL            -1
#define CERT_NAME       "mycert.pem"

int open_SSL_listener(int port) {
    struct sockaddr_in addr;
    int    sd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {
        perror("can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

int is_root() {
    return (getuid() == 0);
}

SSL_CTX* init_SSL_CTX(void) {
    SSL_CTX    *ctx;

    OpenSSL_add_all_algorithms();   // load & register all cryptos, etc.
    SSL_load_error_strings();       // load all error messages
    const SSL_METHOD *method = TLS_method();  // create new server-method instance
    ctx = SSL_CTX_new(method);      // create new context from method
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void load_cert_key(SSL_CTX* ctx, char* cert, char* key) {
    // set the local certificate from cert
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // set the private key from key (may be the same as cert)
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void show_certs(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); // Get certificates (if available)
    if (cert != NULL) {
        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

void read_client(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int  sd;
    int  bytes;
    const char* response = "<body>"
                             "<name>aticleworld.com</name>"
                             "<year>1.5</year>"
                             "<blogtype>Embedede and C/C++</blogtype>"
                             "<author>amlendra</author>"
                           "</body>";

    const char *valid_msg = "<body>"
                              "<username>aticle</username>"
                              "<password>123</password>"
                            "</body>";

    if ( SSL_accept(ssl) == FAIL ) {                // do SSL-protocol accept
        ERR_print_errors_fp(stderr);
    } else {
        X509 *client_cert = SSL_get_peer_certificate(ssl);
        if (client_cert) {
            if (SSL_get_verify_result(ssl) == X509_V_OK) {
                // Client certificate is valid.
                show_certs(ssl);                            // Show local certificates
                memset(buf, 0, sizeof(buf));
                bytes = SSL_read(ssl, buf, sizeof(buf));    // Read client request

                printf("Client msg: [%s]\n", buf);
                if (bytes > 0) {
                    if(strcmp(valid_msg, buf) == 0) {
                        SSL_write(ssl, response, strlen(response));                   // send valid reply
                    } else {
                        SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); // send reply
                    }
                } else {
                    ERR_print_errors_fp(stderr);
                }
            } else {
                printf("Client certificate is not valid\n");
                return;
            }
            X509_free(client_cert);
        } else {
            printf("Client did not provide a certificate\n");
            return;
        }

    }
    sd = SSL_get_fd(ssl);        // get socket connection
    SSL_free(ssl);               // release SSL state
    close(sd);                   // close connection
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    int      sock;
    char    *port_num;

    //Only root user have the permsion to run the server
    if(!is_root()) {
        printf("This program must be run as root/sudo user!!\n");
        exit(0);
    }

    if ( argc != 2 ) {
        printf("Usage: %s <port_num>\n", argv[0]);
        exit(0);
    }

    port_num = argv[1];

    // Initialize the SSL library
    SSL_library_init();
    ctx = init_SSL_CTX();                         // initialize SSL
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
    load_cert_key(ctx, CERT_NAME, CERT_NAME);     // load certificate
    sock = open_SSL_listener(atoi(port_num));     // create server socket
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); // Client certificate required and verify
    SSL_CTX_load_verify_locations(ctx, "ca_cert.crt", NULL);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl = SSL_new(ctx);                                   // get new SSL state with context
        int client = accept(sock, (struct sockaddr*)&addr, &len);  // accept connection as usual
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        SSL_set_fd(ssl, client);                                   // set connection socket to SSL state
        read_client(ssl);                                          // service connection
    }

    close(sock);          // close server socket
    SSL_CTX_free(ctx);    // release context
}
