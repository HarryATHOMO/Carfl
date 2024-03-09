#pragma once

#include <netinet/in.h>
#include <sys/poll.h>
#include <vector>
#include <list>

#include "IClientSocket.h"
#include "Messages.h"
#include "Errors.h"

namespace Network
{
using HeaderType = uint16_t;
static const unsigned int HeaderSize = sizeof(HeaderType);

class ClientSocket : public IClientSocket
{
public:
    enum class State {
        Connecting,
        Connected,
        Disconnected,
    };

private:
    class ConnectionHandler
    {
    public:
        ConnectionHandler() = default;
        bool connect(int sckt, const std::string& address, unsigned short port);
        std::unique_ptr<Messages::Connection> poll();
        const sockaddr_in& connectedAddress() const;

    private:
        pollfd fd_{ 0 };
        sockaddr_in connectedAddress_;
        std::string address_;
        unsigned short port_;
    };

    class ReceptionHandler
    {
        enum class ReceptionState {
            Header,
            Data,
        };
    public:
        ReceptionHandler() = default;
        void init(int sckt, SSL* ssl);
        std::unique_ptr<Messages::Base> recv();

    private:
        inline char* missingDataStartBuffer() {
            return reinterpret_cast<char*>(buffer_.data() + received_);
        }
        inline int missingDataLength() const {
            return static_cast<int>(buffer_.size() - received_);
        }
        void startHeaderReception();
        void startDataReception();
        void startReception(unsigned int expectedDataLength, ReceptionState newState);

    private:
        std::vector<unsigned char> buffer_;
        unsigned int received_;
        int socket_{ INVALID_SOCKET };
        SSL* ssl_ = nullptr;
        ReceptionState state_;
    };

    class SendingHandler
    {
        enum class SendingState {
            Idle,
            Header,
            Data,
        };
    public:
        SendingHandler() = default;
        void init(int sckt, SSL* ssl);
        bool send(const unsigned char* data, unsigned int datalen);
        void update();
        size_t queueSize() const;

    private:
        bool sendPendingBuffer();
        void prepareNextHeader();
        void prepareNextData();

    private:
        std::list<std::vector<unsigned char>> queueingBuffers_;
        std::vector<unsigned char> sendingBuffer_;
        int socket_{ INVALID_SOCKET };
        SSL* ssl_;
        SendingState state_{ SendingState::Idle } ;
    };

private:
    sockaddr_in address_{ 0 };
    int socket_ { INVALID_SOCKET };
    State state_ { State::Disconnected };
    SSL* ssl_;
    ConnectionHandler connectionHandler_;
    SendingHandler sendingHandler_;
    ReceptionHandler receivingHandler_;

public:
    virtual ~ClientSocket();
    ClientSocket();
    ClientSocket(const ClientSocket&) = delete;
    ClientSocket& operator=(const ClientSocket&) = delete;
    ClientSocket(ClientSocket&&);
    ClientSocket& operator=(ClientSocket&&);

private:
    bool init(int&& sckt, const sockaddr_in& addr, ISecu* secu) override;
    bool connect(const std::string& ipaddress, unsigned short port) override;
    void disconnect() override;
    bool send(const unsigned char* data, unsigned int len) override;
    std::unique_ptr<Messages::Base> poll() override;

    uint64_t id() const override;
    const sockaddr_in& destinationAddress() const override;
    void onConnected(const sockaddr_in& addr, SSL* ssl);
};
}