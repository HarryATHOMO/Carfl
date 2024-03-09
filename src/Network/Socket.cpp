#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h> // hton*, ntoh*, inet_addr
#include <fcntl.h>
#include <string>
#include "Socket.h"

namespace Network
{
bool SetNonBlocking(int socket)
{
    return fcntl(socket, F_SETFL, O_NONBLOCK) != -1;
}

std::string GetAddress(const sockaddr_in& addr)
{
    char buff[INET6_ADDRSTRLEN] = { 0 };
    if (auto ret = inet_ntop(addr.sin_family, (void*) & (addr.sin_addr), buff, INET6_ADDRSTRLEN)) {
        return ret;
    }
    return "";
}

unsigned short GetPort(const sockaddr_in& addr)
{
    return ntohs(addr.sin_port);
}
}
