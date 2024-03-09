#pragma once 

#include "ISecu.h"

namespace Network
{
class Secu : public ISecu
{
private:
    SSL_CTX *ctx_;
    int sock_, ctxMethod_;
    std::string certFile_;
    std::string keyFile_;

public:
    Secu();

private:
    void initSecu() override;
    SSL* acceptNewClient(int sockClient) override;
    void configure(const std::string& certFile, const std::string& keyFile, int ctxMethod) override;
    void clear() override;
    virtual ~Secu();

private:
    void loadCertificates(SSL_CTX* ctx);
    SSL_CTX* initSSLContext(int ctxMethod);
    void makekCert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
};
}