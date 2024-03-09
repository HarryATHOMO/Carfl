#pragma once

#include <map>
#include <list>
#include <memory>
#include "IServerSocket.h"
#include "IClientSocket.h"
#include "ISecu.h"



namespace Network
{
class ServerSocket : public IServerSocket
{

private:
    int serverSocket_;
    int port_;
    ISecu* secu_;

    std::map<uint64_t, std::shared_ptr<IClientSocket>> clients_;
    std::list<std::unique_ptr<Messages::Base>> messages_;

    static constexpr uint8_t NBRE_NX_CLIENT = 10;


private:
    bool start(unsigned short _port, bool nonBlockingServer = true, bool listenFromAll = true) override;
    void stop() override;
    void update() override;
    bool sendTo(uint64_t clientid, const unsigned char* data, unsigned int len) override;
    bool sendToAll(const unsigned char* data, unsigned int len) override;
    std::unique_ptr<Messages::Base> poll() override;
    void process() override;
    unsigned int getPortUsed() override;
    bool SetReuseAddr();


public:
    virtual ~ServerSocket();
    ServerSocket();
    ServerSocket(const ServerSocket&) = delete;
    ServerSocket& operator=(const ServerSocket&) = delete;
    ServerSocket(ServerSocket&&);
    ServerSocket& operator=(ServerSocket&&);
};

}