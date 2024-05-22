#include <RestApiHandler/Inscription.h>
#include<Common/Utils/Utils.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Utils;
using namespace Common::Network;

HttpResponse Inscription::process(HttpRequest* req)
{
    auto psql_= getPSQL();
    if (psql_!= nullptr)
    {
        return HttpResponse(ResponseErrorCode::Forbidden, "service non disponible essayer ");
    }
    const Json::Value requestBody = req->getBody();
    std::string nom = requestBody["nom"].asString();
    std::string prenom = requestBody["prenom"].asString();
    std::string email = requestBody["email"].asString();
    std::string phone = requestBody["phone"].asString();
    std::string password = requestBody["password"].asString();
    
    bool ret =     (not nom.empty() and nom.size() <= 20)
                or (not prenom.empty() and prenom.size() <= 20)
                or not str::isValidEmail(email)
                or not str::isValidPassword(password)
                or (phone.empty() or str::isValidPhone(phone));
    if (not ret)
        return HttpResponse(ResponseErrorCode::Bad_Request);
   
    std::string query = "SELECT * FROM Inscription('" + nom + "','" + prenom + "','" + phone + "', '" + email + "','" + password + "');";
    auto res = psql_->processQuery(query);

    if (res.columns() > 0)
    {
        if (res[0].as<int>())
            return HttpResponse(ResponseCode::OK,"");
        else 
            return HttpResponse(ResponseErrorCode::Forbidden);
    }
}
}


} 
