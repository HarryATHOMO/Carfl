#include <sys/socket.h>
#include <arpa/inet.h> // hton*, ntoh*, inet_addr
#include <unistd.h>  // close
#include <cassert>
#include <numeric>
#include <cstring>
#include <limits>
#include <memory>
#include <iostream>
#include <openssl/err.h>
#include "ClientSocket.h"
#include "Socket.h"


namespace Network
{

ClientSocket::~ClientSocket()
{
    disconnect();
}

ClientSocket::ClientSocket()
{
    ssl_ = nullptr;
}
    
ClientSocket::ClientSocket(ClientSocket&& aSocket)
{
    *this = std::move(aSocket);
}

ClientSocket& ClientSocket::operator=(ClientSocket&& aSocket)
{
    *this = std::move(aSocket);
    return *this;
}

bool ClientSocket::init(int&& sckt, const sockaddr_in& addr, ISecu* secu)
{
    if (sckt == INVALID_SOCKET) {
        return false;
    }

    assert(state_ == State::Disconnected);
    assert(socket_ == INVALID_SOCKET);
    if (socket_ != INVALID_SOCKET) {
        disconnect();
    }

    socket_ = sckt;
    if (!SetNonBlocking(socket_)) {
        disconnect();
        return false;
    }

    if (secu != nullptr)
    {
        ssl_ = secu->acceptNewClient(socket_);

        if (ssl_ == nullptr)
        {
            disconnect();
            return false;
        }
    }

    onConnected(addr, ssl_);
    return true;
}

bool ClientSocket::connect(const std::string& ipaddress, unsigned short port)
{
    assert(state_ == State::Disconnected);
    assert(socket_ == INVALID_SOCKET);
    if (socket_ != INVALID_SOCKET) {
        disconnect();
    }

    socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_ == INVALID_SOCKET) {
        return false;
    } else if (!SetNonBlocking(socket_)) {
        disconnect();
        return false;
    }
    if (connectionHandler_.connect(socket_, ipaddress, port)) {
        state_ = State::Connecting;
        return true;
    }
    return false;
}

bool ClientSocket::send(const unsigned char* data, unsigned int len)
{
    return sendingHandler_.send(data, len);
}
    
std::unique_ptr<Messages::Base> ClientSocket::poll()
{
    switch (state_) {
    case State::Connecting: {
        auto msg = connectionHandler_.poll();
        if (msg) {
            if (msg->result == Messages::Connection::Result::Success) {
                onConnected(connectionHandler_.connectedAddress(), ssl_);
            } else {
                disconnect();
            }
        }
        return std::move(msg);
    }
    break;
    case State::Connected: {
        sendingHandler_.update();
        auto msg = receivingHandler_.recv();
        if (msg) {
            if (msg->is<Messages::Disconnection>()) {
                disconnect();
            }
        }
        return msg;
    }
    break;
    case State::Disconnected: {
    } break;
    }
    return nullptr;
}


uint64_t ClientSocket::id() const
{
    return (ssl_ == nullptr) ? static_cast<uint64_t>(socket_) : SSL_get_fd(ssl_);
}
    
const sockaddr_in& ClientSocket::destinationAddress() const
{
    return address_;
}


void ClientSocket::disconnect()
{
    if (socket_ != INVALID_SOCKET) {
        if (ssl_)
        {
            int sock = SSL_get_fd(ssl_); // get traditionnal socket connection from SSL connection
            int ret = SSL_shutdown(ssl_);
            SSL_free(ssl_); 
            close(sock);
        }
        else
        {
            close(socket_);
        }
    }

    socket_ = INVALID_SOCKET;
    state_ = State::Disconnected;
}

void ClientSocket::onConnected(const sockaddr_in& addr, SSL* ssl)
{
    address_ = addr;
    sendingHandler_.init(socket_, ssl);
    receivingHandler_.init(socket_, ssl);
    state_ = State::Connected;
}

const sockaddr_in& ClientSocket::ConnectionHandler::connectedAddress() const {
    return connectedAddress_;
}

bool ClientSocket::ConnectionHandler::connect(int sckt, const std::string& address, unsigned short port)
{
    assert(sckt != INVALID_SOCKET);
    address_ = address;
    port_ = port;
    fd_.fd = sckt;
    fd_.events = POLLOUT;
    inet_pton(AF_INET, address.c_str(), &connectedAddress_.sin_addr.s_addr);
    connectedAddress_.sin_family = AF_INET;
    connectedAddress_.sin_port = htons(port_);
    if (::connect(sckt, (const sockaddr*)&connectedAddress_, sizeof(connectedAddress_)) != 0) {
        int err = Errors::Get();
        if (err != Errors::INPROGRESS && err != Errors::WOULDBLOCK) {
            return false;
        }
    }
    return true;
}

std::unique_ptr<Messages::Connection> ClientSocket::ConnectionHandler::poll()
{
    int res = ::poll(&fd_, 1, 0);
    if (res < 0) {
        return std::make_unique<Messages::Connection>(Messages::Connection::Result::Failed);
    } else if (res > 0) {
        if (fd_.revents & POLLOUT) {
            return std::make_unique<Messages::Connection>(Messages::Connection::Result::Success);
        } else if (fd_.revents & (POLLHUP | POLLNVAL)) {
            return std::make_unique<Messages::Connection>(Messages::Connection::Result::Failed);
        } else if (fd_.revents & POLLERR) {
            return std::make_unique<Messages::Connection>(Messages::Connection::Result::Failed);
        }
    }
    //!< action non termin�e
    return nullptr;
}

void ClientSocket::ReceptionHandler::init(int sckt, SSL* ssl)
{
    assert(sckt != INVALID_SOCKET);
    socket_ = sckt;
    ssl_ = ssl;
    startHeaderReception();
}
void ClientSocket::ReceptionHandler::startHeaderReception()
{
    startReception(HeaderSize, ReceptionState::Header);
}
void ClientSocket::ReceptionHandler::startDataReception()
{
    assert(buffer_.size() == sizeof(HeaderType));
    HeaderType networkExpectedDataLength;
    memcpy(&networkExpectedDataLength, buffer_.data(), sizeof(networkExpectedDataLength));
    const auto expectedDataLength = ntohs(networkExpectedDataLength);
    startReception(expectedDataLength, ReceptionState::Data);
}
void ClientSocket::ReceptionHandler::startReception(unsigned int expectedDataLength, ReceptionState newState)
{
    received_ = 0;
    buffer_.clear();
    buffer_.resize(expectedDataLength, 0);
    state_ = newState;
}
std::unique_ptr<Messages::Base> ClientSocket::ReceptionHandler::recv()
{
    assert(socket_ != INVALID_SOCKET);

    //bytes = SSL_read(ssl_, buf, sizeof(buf));
    /*char buf[1024], reply[1024];
    int bytes;
    const char *echo = "Enchante %s, je suis ServerName.\n";*/

    int ret = (ssl_ != nullptr) ?
                SSL_read(ssl_, missingDataStartBuffer(), missingDataLength()) :
                ::recv(socket_, missingDataStartBuffer(), missingDataLength(), 0);
    if (ret > 0) {
        received_ += ret;
        if (received_ == buffer_.size()) {
            if (state_ == ReceptionState::Data) {
                std::unique_ptr<Messages::Base> msg = std::make_unique<Messages::UserData>(std::move(buffer_));
                startHeaderReception();
                return msg;
            } else {
                startDataReception();
                //!< si jamais les donn�es sont d�j� disponibles elles seront ainsi retourn�es directement
                return recv();
            }
        }
        return nullptr;
    } else if (ret == 0) {
        //!< connexion termin�e correctement
        return std::make_unique<Messages::Disconnection>(Messages::Disconnection::Reason::Disconnected);
    } else { // ret < 0
        //!< traitement d'erreur
        int error = Errors::Get();
        if (error == Errors::WOULDBLOCK || error == Errors::AGAIN) {
            return nullptr;
        } else {
            return std::make_unique<Messages::Disconnection>(Messages::Disconnection::Reason::Lost);
        }
    }
}

void ClientSocket::SendingHandler::init(int sckt, SSL* ssl)
{
    socket_ = sckt;
    if (state_ == SendingState::Header || state_ == SendingState::Data) {
        sendingBuffer_.clear();
    }
    state_ = SendingState::Idle;
    ssl_ = ssl;
}
bool ClientSocket::SendingHandler::send(const unsigned char* data, unsigned int datalen)
{
    if (datalen > std::numeric_limits<HeaderType>::max()) {
        return false;
    }
    queueingBuffers_.emplace_back(data, data + datalen);
    return true;
}
void ClientSocket::SendingHandler::update()
{
    assert(socket_ != INVALID_SOCKET);
    
    if (state_ == SendingState::Idle && !queueingBuffers_.empty()) {
        prepareNextHeader();
    }
    while (state_ != SendingState::Idle && sendPendingBuffer()) {
        if (state_ == SendingState::Header) {
            prepareNextData();
        } else {
            if (!queueingBuffers_.empty()) {
                prepareNextHeader();
            } else {
                state_ = SendingState::Idle;
            }
        }
    }
}
bool ClientSocket::SendingHandler::sendPendingBuffer()
{
    if (sendingBuffer_.empty()) {
        return true;
    }

    //!< envoi des donn�es restantes du dernier envoi
    int sent = (ssl_ != nullptr) ?
                SSL_read(ssl_, reinterpret_cast<char*>(sendingBuffer_.data()), static_cast<int>(sendingBuffer_.size())) :
                ::send(socket_, reinterpret_cast<char*>(sendingBuffer_.data()), static_cast<int>(sendingBuffer_.size()), 0);
    
    if (sent > 0) {
        if (sent == sendingBuffer_.size()) {
            //!< toutes les donn�es ont �t� envoy�es
            sendingBuffer_.clear();
            return true;
        } else {
            //!< envoi partiel
            memmove(sendingBuffer_.data() + sent, sendingBuffer_.data(), sent);
            sendingBuffer_.erase(sendingBuffer_.begin() + sent, sendingBuffer_.end());
        }
    }
    return false;
}
void ClientSocket::SendingHandler::prepareNextHeader()
{
    assert(!queueingBuffers_.empty());
    const auto header = static_cast<HeaderType>(queueingBuffers_.front().size());
    const auto networkHeader = htons(header);
    sendingBuffer_.clear();
    sendingBuffer_.resize(HeaderSize);
    memcpy(sendingBuffer_.data(), &networkHeader, sizeof(HeaderType));
    state_ = SendingState::Header;
}
void ClientSocket::SendingHandler::prepareNextData()
{
    assert(!queueingBuffers_.empty());
    sendingBuffer_.swap(queueingBuffers_.front());
    queueingBuffers_.pop_front();
    state_ = SendingState::Data;
}
size_t ClientSocket::SendingHandler::queueSize() const
{
    size_t s = std::accumulate(queueingBuffers_.cbegin(), queueingBuffers_.cend(), static_cast<size_t>(0), [](size_t n, const std::vector<unsigned char>& queuedItem) {
        return n + queuedItem.size() + HeaderSize;
    });
    if (state_ == SendingState::Data) {
        s += sendingBuffer_.size();
    }
    return s;
}
}

