#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define CERT_NAME       "mycert.pem"

int open_SSL_connection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }

    return sd;
}

SSL_CTX* init_SSL_CTX(void) {
    SSL_CTX    *ctx;

    OpenSSL_add_all_algorithms();                        // Load cryptos, et.al.
    SSL_load_error_strings();                            // Bring in and register error messages
    const SSL_METHOD *method = TLS_method();             // Create new client method instance
    ctx = SSL_CTX_new(method);                           // Create new context

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void show_certificates(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);                 // get the server_sock's certificate
    if (cert != NULL) {
        printf("server certificate:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    } else {
        printf("Info: No peer certificates available");
    }
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


int main_client(int argc, char *argv[]) {
    int      server_sock;
    char     buf[1024];
    int      bytes;
    char    *hostname;
    char    *port_num;
    SSL     *ssl;
    SSL_CTX *ctx;
    char     client_request[1024] = {0};

    if (argc != 3) {
        printf("usage: %s <hostname> <port_num>\n", argv[0]);
        exit(0);
    }

    hostname = argv[1];
    port_num = argv[2];

    SSL_library_init();
    ctx = init_SSL_CTX();
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_VERSION);
    load_cert_key(ctx, CERT_NAME, CERT_NAME);     // load certificate

    server_sock = open_SSL_connection(hostname, atoi(port_num));
    ssl = SSL_new(ctx);                 // create new SSL connection state
    SSL_set_fd(ssl, server_sock);       // attach the socket descriptor
    if (SSL_connect(ssl) == FAIL) {     // perform the connection
        ERR_print_errors_fp(stderr);
    } else {
        char username[16] = {0};
        char password[16] = {0};
        const char *request = "<body>"
                                "<username>%s</username>"
                                "<password>%s</password>"
                              "</body>";

        printf("Enter the Username: ");
        scanf("%s", username);

        printf("Enter the Password: ");
        scanf("%s", password);

        sprintf(client_request, request, username, password);           // Construct message/
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        show_certificates(ssl);                                         // show peer certificate
        SSL_write(ssl, client_request, strlen(client_request));         // encrypt & send message

        memset(buf, 0, sizeof(buf));
        bytes = SSL_read(ssl, buf, sizeof(buf));                        // get reply & decrypt
        printf("Received message: [%s]\n", buf);
        SSL_free(ssl);                                                  // release connection state
    }

    close(server_sock);                                                 // close socket
    SSL_CTX_free(ctx);                                                  // release context
    return 0;
}

int main(int argc, char *argv[]) {
    printf("Something\n");
}
