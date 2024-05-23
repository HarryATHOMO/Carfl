#pragma once

#include <Common/Network/RestApi/IHandler.h> 

namespace CarflowServer
{
namespace RestApiHandler
{
class Inscription : public Common::Network::RestApi::IHandler
{
public:
    virtual ~Inscription() {}
    Common::Network::HttpResponse process(Common::Network::HttpRequest*) final override;
};
}
}