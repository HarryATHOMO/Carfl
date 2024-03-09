#include <sys/socket.h>
#include <netinet/in.h> // sockaddr_in, IPPROTO_TCP
#include <arpa/inet.h> // hton*, ntoh*, inet_addr
#include <unistd.h>  // close
#include <cerrno> // errno
#include <poll.h> // poll
#include <string>
#include <cassert>
#include <iostream>

#include "ServerSocket.h"
#include "ClientSocket.h"
#include "Socket.h"
#include "Secu.h"


namespace Network
{

ServerSocket::ServerSocket()
{
    serverSocket_ = INVALID_SOCKET;
    int port_ = -1;

    secu_ = new Secu();
    secu_->configure("/home/adris/CarflowServer/serverKey/server.crt", "/home/adris/CarflowServer/serverKey/server.key", 1);
    secu_->initSecu();
}

ServerSocket::~ServerSocket()
{
    secu_->clear();
}

ServerSocket::ServerSocket(ServerSocket&& aSocket)
{
    *this = std::move(aSocket);
}

ServerSocket& ServerSocket::operator=(ServerSocket&& aServerSocket)
{
    *this = std::move(aServerSocket);
    return *this;
}


bool ServerSocket::start(unsigned short port, bool nonBlockingServer, bool listenFromAll)
{
    assert(serverSocket_ == INVALID_SOCKET);

    if (serverSocket_ != INVALID_SOCKET) {
        stop();
    }

    serverSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (serverSocket_ == INVALID_SOCKET) {
        return false;
    }

    if (!SetReuseAddr() || !(nonBlockingServer && SetNonBlocking(serverSocket_))) {
        stop();
        return false;
    }

    sockaddr_in addr;
    addr.sin_addr.s_addr = (listenFromAll) ? INADDR_ANY : inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    port_ = port;

    if (bind(serverSocket_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        stop();
        return false;
    }

    if (listen(serverSocket_, SOMAXCONN) != 0) {
        stop();
        return false;
    }

    return true;
}

void ServerSocket::stop()
{
    for (auto& client : clients_) {
        client.second->disconnect();
    }

    clients_.clear();

    if (serverSocket_ != INVALID_SOCKET) {
        close(serverSocket_);
    }

    serverSocket_ = INVALID_SOCKET;
}

void ServerSocket::update()
{
    if (serverSocket_ == INVALID_SOCKET) {
        return;
    }

    //!< accept jusqu'� 10 nouveaux clients
    for (uint8_t accepted = 0; accepted < NBRE_NX_CLIENT; ++accepted) {
        sockaddr_in addr = { 0 };
        socklen_t addrlen = sizeof(addr);
        int newClientSocket = accept(serverSocket_, reinterpret_cast<sockaddr*>(&addr), &addrlen);

        if (newClientSocket == INVALID_SOCKET) {
            break;
        }


    /*char buf[1024], reply[1024];
    int bytes;
    const char *echo = "Enchante %s, je suis ServerName.\n";

    bytes = SSL_read(ssl, buf, sizeof(buf));

    if (bytes > 0)
        {
            buf[bytes] = 0;
            printf("[+] Client data received : %s\n", buf);
            sprintf(reply, echo, buf);            // construct response
            SSL_write(ssl, reply, std::strlen(reply)); // send response
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
        }*/
        

        IClientSocket* newClient = new ClientSocket();

        if (newClient->init(std::move(newClientSocket), addr, secu_)) {
            auto message = std::make_unique<Messages::Connection>(Messages::Connection::Result::Success);
            message->idFrom = newClient->id();
            message->from = newClient->destinationAddress();
            messages_.push_back(std::move(message));
            clients_[newClient->id()] = std::shared_ptr<IClientSocket>(newClient);
        }
    }

    //!< mise � jour des clients connect�s
    //!< r�ceptionne au plus 1 message par client
    //!< supprime de la liste les clients d�connect�s
    for (auto itClient = clients_.begin(); itClient != clients_.end();) {
        auto& client = itClient->second;
        auto msg = client->poll();

        if (msg) {
            msg->from = itClient->second->destinationAddress();
            msg->idFrom = itClient->second->id();

            if (msg->is<Messages::Disconnection>()) {
                itClient = clients_.erase(itClient);
            } else {
                ++itClient;
            }

             messages_.push_back(std::move(msg));
        } else {
            ++itClient;
        }
    }
}

bool ServerSocket::sendTo(uint64_t clientid, const unsigned char* data, unsigned int len)
{
    auto itClient = clients_.find(clientid);
    return (itClient != clients_.end()) && itClient->second->send(data, len);
}

bool ServerSocket::sendToAll(const unsigned char* data, unsigned int len)
{
    bool ret = true;

    for (auto& client : clients_) {
        ret &= client.second->send(data, len);
    }

    return ret;
}

std::unique_ptr<Messages::Base> ServerSocket::poll()
{
    if (messages_.empty()) {
        return nullptr;
    }

    auto msg = std::move(messages_.front());
    messages_.pop_front();
    return msg;
}

void ServerSocket::process()
{

}

bool ServerSocket::SetReuseAddr()
{
    int optval = 1;
    return setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == 0;
}

unsigned int ServerSocket::getPortUsed()
{
    return port_;
}

}