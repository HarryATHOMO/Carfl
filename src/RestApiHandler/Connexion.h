#pragma once

#include <Common/Network/RestApi/IHandler.h> 


namespace CarflowServer
{
namespace RestApiHandler
{
class Connexion : public Common::Network::RestApi::IHandler
{
public:
    Common::Network::HttpResponse process(Common::Network::HttpRequest*) final override;
};
}
}