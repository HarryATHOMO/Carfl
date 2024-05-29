#include <RestApiHandler/Inscription.h>
#include<Common/Utils/Utils.h>
#include <Common/Utils/Token.h>
#include <Common/Network/RestApi/Server.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Utils;
using namespace Common::Network;

HttpResponse Inscription::process(HttpRequest* req)
{
    auto psql_= getPSQL();
    if (psql_== nullptr)
    {
        return HttpResponse(ResponseErrorCode::service_unavailable, "service non disponible. Reessayez plus tard");
    }

    const Json::Value requestBody = req->getBody();
    std::string username = requestBody["username"].asString();
    std::string nom = requestBody["nom"].asString();
    std::string prenom = requestBody["prenom"].asString();
    std::string email = requestBody["email"].asString();
    std::string phone = requestBody["phone"].asString();
    std::string password = requestBody["password"].asString();
    std::string naissance = requestBody["naissance"].asString();
    std::string contact = requestBody["contact"].asString();
    int sexe = requestBody["sexe"].asUInt();
    
    bool ret =     (not nom.empty() and nom.size() <= 20)
                and (username.size() >= 8 and username.size() <= 20)
                and (not prenom.empty() and prenom.size() <= 20)
                and (not phone.empty() or not email.empty())
                and (email.empty() or str::isValidEmail(email))
                and (not password.empty() and str::isValidPassword(password))
                and (phone.empty() or str::isValidPhone(phone))
                and (not naissance.empty() and str::isValidBirthDate(naissance, "%d-%m-%Y"))
                and (contact.empty() or (contact == "phone" or contact == "email"))
                and (sexe == 1 or sexe == 2);
    if (not ret)
        return HttpResponse(ResponseErrorCode::Bad_Request, "Champs manquants ou mauvais format des données");
   
    if (contact.empty())
    {
        contact = "email";
    }

    std::string query = "SELECT * FROM Inscription('" + username + "'," + std::to_string(sexe) + ", '" + nom + "','" + prenom + "','" + phone + "', '" + email + "','" + password + "', ,'" + naissance + "', ,'" + contact + "');";
    auto res = psql_->processQuery(query);

    if (res.size() == 0 or not res[0][0].as<bool>())
    {
        return HttpResponse(ResponseErrorCode::Forbidden);
    }

    std::string id = res[0][1].as<std::string>();
    auto tok = Token::generateRandomToken(25); 
    auto code = Token::generateCode(6);

    if (contact == "email")
    {
        auto emailMngr = server_->getEmailManager();
        if (emailMngr != nullptr and str::isValidEmail(email))
        {
            emailMngr->sendEmail(email, "Confirmation de compte", "code : " + code, [&](uint res){
                if (res)
                {
                    auto serv = dynamic_cast<RestApi::Server*>(server_);

                    if (serv != nullptr)
                    {
                        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                        serv->addCodeValidate(tok, {now, code, id});
                    }
                }
            });
        }
    }
    
    return HttpResponse(ResponseCode::OK, "{\"token\" : \"" + tok + "\" }");
}
}


} 
