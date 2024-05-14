#include <RestApiHandler/Inscription.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Network;

HttpResponse Inscription::process(HttpRequest* req)
{
    const Json::Value requestBody = req->getBody();

    HttpResponse resp(ResponseErrorCode::Bad_Request);

    return resp;

    /*std::string username = requestBody["username"].asString();
    std::string email = requestBody["email@xyg.com"].asString();
    std::string password = requestBody["password"].asString();
    std::string numeTel = requestBody["+241 0000000"].asString();

    // Vérification si ils ne sont pas vides
    if (username.empty() || email.empty() || password.empty() || numeTel.empty()) {
        return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Bad_Request);
    }

Connexion à la base de données PostgreSQL
    PGconn* conn = PQconnectdb("host=192.168.0.19 dbname=db_test2 user=postgres ");
    if (!conn || PQstatus(conn) != CONNECTION_OK) {
       return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Internal_Server_Error);
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
        return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Internal_Server_Error);
    }

   PQclear(res);
    PQfinish(conn);

    return Common::Network::HttpResponse(Common::Network::ResponseErrorCode::Bad_Request);*/
}
}


} 
