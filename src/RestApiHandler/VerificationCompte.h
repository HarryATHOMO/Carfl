#pragma once

#include <Common/Network/RestApi/IHandler.h> 

namespace CarflowServer
{
namespace RestApiHandler
{
class VerificationCompte : public Common::Network::RestApi::IHandler
{
public:
    virtual ~VerificationCompte() {}
    Common::Network::HttpResponse process(Common::Network::HttpRequest*) final override;
};
}
}