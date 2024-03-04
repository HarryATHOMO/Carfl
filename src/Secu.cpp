/** SSL/TLS Server
 * SSL/TLS server demonstration. This source code is cross-plateforme Windows and Linux.
 * Compile under Linux with : g++ main.cpp -Wall -lssl -lcrypto -o main
 * Certificat and private key to protect transaction can be used from :
 * - External(s) file(s), created with command : openssl req -x509 -nodes -newkey rsa:2048 -keyout server.pem -out server.pem
 * - Internal uniq hardcoded certificat and private key, equal into each server instance
 * - Randomly generated certificat and private key, best solution to used dynamic keying material at each server lauching.
 * Usage :
 * # run the server on port 1337 for SSLv2&3 protocol with internals key and certificat
 * $ [./]server[.exe] 1337
 * # run the server on port 1337 for TLSv1 protocol with key and certificat in server.pem file
 * $ [./]server[.exe] 1337 1 server.pem server.pem
 * @author x@s
 */

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string>
#include <exceptions.h>

#include <openssl/crypto.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include "Secu.h"

/**
 * makekCert function who create the server certificat containing public key and
 * the server private key signed (dynamic method).
 * @param X509 **x509p : potential previous instance of X509 certificat
 * @param EVP_PKEY **pkeyp : potential previous instance of private key
 * @param int bits : length of the RSA key to generate (precaunized greater than or equal 2048b)
 * @param int serial : long integer representing a serial number
 * @param int days : number of valid days of the certificat
 * @see Inpired from /demos/x509/mkcert.c file of OpenSSL library.
 */
/*void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days){
X509 *x;
EVP_PKEY *pk;
RSA *rsa;
X509_NAME *name = NULL;

if((pkeyp == NULL) || (*pkeyp == NULL)){
if((pk = EVP_PKEY_new()) == NULL)
abort();
} else
pk= *pkeyp;
if((x509p == NULL) || (*x509p == NULL)){
if ((x = X509_new()) == NULL)
abort();
} else
x= *x509p;

// create RSA key
rsa = RSA_generate_key(bits, RSA_F4, callbackGeneratingKey, NULL);
if(!EVP_PKEY_assign_RSA(pk, rsa))
abort();
rsa = NULL;

X509_set_version(x, 2); // why not 3 ?
ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
X509_gmtime_adj(X509_get_notBefore(x), 0); // define validation begin cert
X509_gmtime_adj(X509_get_notAfter(x), (long)60*60*24*days); // define validation end cert
X509_set_pubkey(x, pk); // define public key in cert
name = X509_get_subject_name(x);

// This function creates and adds the entry, working out the
// correct string type and performing checks on its length.
// Normally we'd check the return value for errors...
X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"XX", -1, -1, 0); // useless if more anonymity needed
X509_NAME_add_entry_by_txt(name,"CN", MBSTRING_ASC, (const unsigned char*)"ASRAT", -1, -1, 0); // useless if more anonymity needed

// Its self signed so set the issuer name to be the same as the subject.
X509_set_issuer_name(x, name);

if(!X509_sign(x, pk, EVP_md5())) // secured more with sha1? md5/sha1? sha256?
abort();

*x509p = x;
*pkeyp = pk;
return;
}*/

/**
 * initSSLContext function who initialize the SSL/TLS engine with right method/protocol
 * @param int ctxMethod : the number coresponding to the method/protocol to use
 * @return SSL_CTX *ctx : a pointer to the SSL context created
 */

SSL_CTX *Secu::initSSLContext(int ctxMethod)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();           // initialize the SSL library
    SSL_load_error_strings();     // bring in and register error messages
    OpenSSL_add_all_algorithms(); // load usable algorithms

    switch (ctxMethod)
    { // create new client-method instance
    case 1:
        method = TLSv1_server_method();
        printf("[+] Use TLSv1 method.\n");
        break;
    // SSLv2 isn't sure and is deprecated, so the latest OpenSSL version on Linux delete his implementation.
    /*case 2 :
    method = SSLv2_server_method();
    printf("[+] Use SSLv2 method.\n");
    break;*/
    case 3:
        method = SSLv3_server_method();
        printf("[+] Use SSLv3 method.\n");
        break;
    case 4:
        method = SSLv23_server_method();
        printf("[+] Use SSLv2&3 method.\n");
        break;
    default:
        method = SSLv23_server_method();
        printf("[+] Use SSLv2&3 method.\n");
    }

    ctx = SSL_CTX_new(method); // create new context from selected method
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/**
 * loadCertificates function who load private key and certificat from files.
 * 3 mecanisms available :
 * - loading certificate and private key from file(s)
 * - use embed hardcoded certificate and private key in the PEM format
 * - generate random and dynamic certificate and private key at each server's launch instance.
 * @param SSL_CTX* ctx : the SSL/TLS context
 * @param char *certFile : filename of the PEM certificat
 * @param char *keyFile : filename of the PEM private key
 */
void Secu::loadCertificates(SSL_CTX *ctx, const char *certFile, const char *keyFile)
{
    
    X509 *cert = nullptr;
    EVP_PKEY *pkey = nullptr;
    // RSA *rsa = NULL; // if internal private key and certificat required
    // BIO *cbio, *kbio; // if internal private key and certificat required

    if (certFile == nullptr || keyFile == nullptr)
    {
        throw std::runtime_error("Server cert file or key file is null");
    }
    else if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0 ||
             SSL_CTX_use_RSAPrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    else
        std::cout<<"[*] Server's certificat and private key loaded from file."<< std::endl;

    // verify private key match the public key into the certificate
    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cout<<(stderr, "[-] Private key does not match the public certificate..."<<std::end;
        abort();
    }
    else
        std::cout<<"[+] Server's private key match public certificat !"<<std::endl;

    return;
}

/**
 * showCerts function who catch and print out certificate's data from the client.
 * @param SSL* ssl : the SSL/TLS connection
 */
void Secu::showCerts(SSL *ssl)
{
    X509 *cert;
    char *subject, *issuer;

    cert = SSL_get_peer_certificate(ssl); // get the client's certificate
    if (cert != NULL)
    {
        subject = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); // get certificate's subject
        issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);   // get certificate's issuer

        printf("[+] Client certificates :\n");
        printf("\tSubject: %s\n", subject);
        printf("\tIssuer: %s\n", issuer);

        free(subject);   // free the malloc'ed string
        free(issuer);    // free the malloc'ed string
        X509_free(cert); // free the malloc'ed certificate copy
    }
    else
        printf("[-] No client's certificates\n");
    return;
}

/**
 * routine function who treat the content of data received and reply to the client.
 * this function is threadable and his context sharedable.
 * @param SSL* ssl : the SSL/TLS connection
 */
void Secu::routine(SSL *ssl)
{
    char buf[1024], reply[1024];
    int sock, bytes;
    const char *echo = "Enchante %s, je suis ServerName.\n";

    if (SSL_accept(ssl) == -1) // accept SSL/TLS connection
        ERR_print_errors_fp(stderr);
    else
    {
        printf("[+] Cipher used : %s\n", SSL_get_cipher(ssl));
        showCerts(ssl);                          // get any client certificates
        bytes = SSL_read(ssl, buf, sizeof(buf)); // read data from client request
        if (bytes > 0)
        {
            buf[bytes] = 0;
            printf("[+] Client data received : %s\n", buf);
            sprintf(reply, echo, buf);            // construct response
            SSL_write(ssl, reply, strlen(reply)); // send response
        }
        else
        {
            switch (SSL_get_error(ssl, bytes))
            {
            case SSL_ERROR_ZERO_RETURN:
                printf("SSL_ERROR_ZERO_RETURN : ");
                break;
            case SSL_ERROR_NONE:
                printf("SSL_ERROR_NONE : ");
                break;
            case SSL_ERROR_SSL:
                printf("SSL_ERROR_SSL : ");
                break;
            }
            ERR_print_errors_fp(stderr);
        }
    }
    sock = SSL_get_fd(ssl); // get traditionnal socket connection from SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);     // release SSL connection state
    CLOSESOCKET(sock); // close socket
}

/**
 * main function who coordinate the socket and SSL connection creation, then receive and emit data to and from the client.
 */
