#pragma once

#include <openssl/ssl.h>

namespace Network
{
class ISecu
{
public:
    virtual void initSecu() = 0;
    virtual SSL* acceptNewClient(int sockClient) = 0;
    virtual void configure(const std::string& certFile, const std::string& keyFile, int ctxMethod) = 0;
    virtual void clear() = 0;
};
}