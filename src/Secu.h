#pragma once 

class Secu
{
public:
    Secu();
    SSL_CTX* initSSLContext(int ctxMethod);

private:
    void loadCertificates(SSL_CTX* ctx, const char* certFile, const char* keyFile);

};