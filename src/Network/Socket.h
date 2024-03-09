#pragma once

namespace Network
{
bool SetNonBlocking(int);
std::string GetAddress(const sockaddr_in& addr);
unsigned short GetPort(const sockaddr_in& addr);
}