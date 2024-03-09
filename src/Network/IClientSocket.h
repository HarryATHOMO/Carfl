#pragma once

#include <string>
#include <memory>
#include <openssl/ssl.h>

#include "Messages.h"
#include "ISecu.h"

namespace Network
{
class IClientSocket
{
public:
    virtual bool init(int&& sckt, const sockaddr_in& addr, ISecu* secu) = 0;
    virtual bool connect(const std::string& ipaddress, unsigned short port) = 0;
    virtual void disconnect() = 0;
    virtual bool send(const unsigned char* data, unsigned int len) = 0;
    virtual std::unique_ptr<Messages::Base> poll() = 0;
    virtual uint64_t id() const = 0;
    virtual const sockaddr_in& destinationAddress() const = 0;
};
}

