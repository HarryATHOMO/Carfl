#include "RestHandlerPackage.h"

#include <RestApiHandler/CodeAuthenticate.h>
#include <RestApiHandler/Connexion.h>
#include <RestApiHandler/Inscription.h>
#include <RestApiHandler/VerificationCompte.h>

namespace CarflowServer
{
using namespace RestApiHandler;

std::map<std::string, std::shared_ptr<Common::Network::RestApi::IHandler>> RestHandlerPackage::getHandlers()
{
    std::map<std::string, std::shared_ptr<Common::Network::RestApi::IHandler>> handlers;

    handlers["codeAuthenticate"] = std::make_shared<CodeAuthentificate>();
    handlers["connexion"] = std::make_shared<Connexion>();
    handlers["inscription"] = std::make_shared<Inscription>();
    handlers["verifyCompte"] = std::make_shared<VerificationCompte>();

    return handlers;
}
};