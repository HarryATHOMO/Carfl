#include "RestHandlerPackage.h"

#include <RestApiHandler/Connexion.h>
#include <RestApiHandler/Inscription.h>

namespace CarflowServer
{
using namespace RestApiHandler;

std::map<std::string, std::shared_ptr<Common::Network::RestApi::IHandler>> RestHandlerPackage::getHandlers()
{
    std::map<std::string, std::shared_ptr<Common::Network::RestApi::IHandler>> handlers;

    handlers["connexion"] = std::make_shared<Connexion>();
    handlers["inscription"] = std::make_shared<Inscription>();
    return handlers;
}
};