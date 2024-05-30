#pragma once

#include <Common/Network/RestApi/IHandler.h> 

namespace CarflowServer
{
namespace RestApiHandler
{
class CodeAuthentificate : public Common::Network::RestApi::IHandler
{
public:
    virtual ~CodeAuthentificate() {}
    Common::Network::HttpResponse process(Common::Network::HttpRequest*) final override;
};
}
}