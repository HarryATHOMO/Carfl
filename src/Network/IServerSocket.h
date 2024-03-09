#pragma once

#include <cstdint>

#include "Messages.h"

namespace Network
{
class IServerSocket
{
public:
    virtual bool start(unsigned short _port, bool nonBlockingServer = true, bool listenFromAll = true) = 0;
    virtual void stop() = 0;
    virtual void update() = 0;
    virtual bool sendTo(uint64_t clientid, const unsigned char* data, unsigned int len) = 0;
    virtual bool sendToAll(const unsigned char* data, unsigned int len) = 0;
    virtual std::unique_ptr<Messages::Base> poll() = 0;
    virtual void process() = 0;
    virtual unsigned int getPortUsed() = 0;
};

}