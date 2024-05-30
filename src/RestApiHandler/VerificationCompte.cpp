#include <src/RestApiHandler/VerificationCompte.h> 
#include <Common/Network/RestApi/Server.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Utils;
using namespace Common::Network;

HttpResponse VerificationCompte::process(Common::Network::HttpRequest* req)
{
    auto psql_= getPSQL();
    if (psql_== nullptr)
    {
        return HttpResponse(ResponseErrorCode::service_unavailable, "service non disponible. Reessayez plus tard");
    }

    std::string token = req->getHeader().bearer;
    std::string identifiant;
    std::string servCode;
    auto serv = dynamic_cast<RestApi::Server*>(server_);
    if (serv != nullptr)
    {
        auto tp = serv->getCodeValidate(token);
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto tmp = std::get<0>(tp);

        uint16_t diff = (now - tmp) * std::chrono::system_clock::period::num / std::chrono::system_clock::period::den;

        if (diff > (15 * 60))
        {
            return HttpResponse(ResponseErrorCode::Forbidden, "token not more valide");
        }

        servCode = std::get<1>(tp);
        identifiant = std::get<2>(tp);
    }

    const Json::Value requestBody = req->getBody();
    std::string code = requestBody["code"].asString();
    
    if (code != servCode)
    {
        return HttpResponse(ResponseErrorCode::Forbidden, "Code not correct");
    }
    
    std::string query = "SELECT * FROM validUser('" + identifiant + "');";
    auto res = psql_->processQuery(query);

    if (res.columns() == 0 or not res[0][0].as<bool>())
    {
        return HttpResponse(ResponseErrorCode::Forbidden);
    }

    serv->deleteCodeValidate(token);

    return HttpResponse(ResponseCode::OK,"");
}
}
}