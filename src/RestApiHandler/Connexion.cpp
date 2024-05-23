#include <RestApiHandler/Connexion.h>
#include <Common/Utils/Utils.h>
#include <Common/Network/RestApi/Server.h>
#include <Common/Database/IPostgreSQL.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Network;
using namespace Common::Utils;
HttpResponse Connexion::process(HttpRequest* req)
{ //pourquoi ici on vérifie pas si la base de donnée est vide ou pas comme dans l'inscription ?//

    const Json::Value requestBody = req->getBody();

    std::string email = requestBody["email"].asString();
    std::string password = requestBody["password"].asString();

    bool ret =      (not email.empty() and str::isValidEmail(email))
                and (not password.empty() and str::isValidPassword(password));

    if (not ret)
    {
        return HttpResponse(ResponseErrorCode::Bad_Request);
    }

    return HttpResponse(ResponseErrorCode::Bad_Request);

    //auto influx = server_->getInfluxDb();
    //auto psql_= getPSQL();
    

    
    /*if (str::isValidEmail(email))
    {

    }

    if (psql_!= nullptr)
    {
        std::stringstream ss;
        ss << "SELECT * FROM getUser(";
        ss << "'" << email << "', '" << password << "'";

        std::string query = ss.str();
        auto res = psql_->processQuery(query);
    }

    

    return resp;

    std::string username = requestBody["username"].asString();
    std::string password = requestBody["password"].asString();

    //Vérification si ils ne sont pas vides
    if (username.empty() || email.empty() || password.empty()) {

        return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Bad_Request);
    }

    //Connexion à la base de données PostgreSQL
    PGconn* conn = PQconnectdb("host=192.168.0.19 dbname=db_test2 user=postgres ");
    if (!conn || PQstatus(conn) != CONNECTION_OK) {
        return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Bad_Request);
    }
    // requête préparée
    const char* query = "SELECT * FROM clients WHERE username = $1 AND email = $2 AND  password  = $3 AND numberphone = $4";
    const char* paramValues[4] = { username.c_str(), password.c_str(), email.c_str(), numeTel.c_str() };
    const int paramLengths[4] = { username.length(), password.length(), email.length(), numeTel.length() };
    const int paramFormats[4] = { 0, 0, 0, 0 };
    PGresult* res = PQexecParams(conn, query, 4, nullptr, paramValues, paramLengths, paramFormats, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        PQfinish(conn);
        return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Bad_Request);
    }
    PQclear(res);
    PQfinish(conn);*/
} 

}
}