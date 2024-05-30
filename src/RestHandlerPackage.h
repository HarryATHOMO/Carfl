#pragma once

#include <Common/Package/ApiRestHandlerPackage.h>

namespace CarflowServer
{
class RestHandlerPackage : public Common::Package::ApiRestHandlerPackage
{
public:
    std::map<std::string, std::shared_ptr<Common::Network::RestApi::IHandler>> getHandlers() override final;
};
}