#include <gtest/gtest.h>
#include <src/RestApiHandler/Inscription.h>
#include <test/Mock/RestApiServer.h>


namespace Test {
namespace RestApiHandler {

using namespace CarflowServer::RestApiHandler;
class InscriptionTest : public ::testing::Test
{
protected:
    Inscription* inscription = nullptr;
    Mock::RestApiServer* server = nullptr;
    Common::Database::MockPostgresSQL* psql = nullptr;

    void TearDown() override
    {
        delete inscription;
        inscription = nullptr;
        delete server;
        server = nullptr;
        delete psql;
        psql = nullptr;
    };

};

TEST_F(InscriptionTest, psqlNull)
{
    server = new Mock::RestApiServer();
    inscription = new Inscription();
    inscription->setServer(server);

    Common::Network::Header h;
    std::string body;
    
    Common::Network::HttpRequest* req = new Common::Network::HttpRequest(std::move(h), std::move(body));

    auto resp = inscription->process(req);

    EXPECT_EQ(resp.getCode(), 503);
    std::string expectedResp = R"({"msg" : "service non disponible. Reessayez plus tard"})";
    EXPECT_STREQ(resp.getMessage().c_str(),  expectedResp.c_str());

    delete req;
}


TEST_F(InscriptionTest, wrong_format)
{
    server = new Mock::RestApiServer();

    inscription = new Inscription();
    inscription->setServer(server);

    Common::Network::Header h;
    std::string body = R"({
                            "nom" : "TOTO",
                            "prenom" : "tata",
                            "email" : "TOTO",
                            "phone" : "TOTO",
                            "password" : "TOTO",
                            "contact" : "email",
                            "naissance" : "bonsoir"
                            })";
    
    Common::Network::HttpRequest* req = new Common::Network::HttpRequest(std::move(h), std::move(body));

    auto resp = inscription->process(req);

    delete req;
}

TEST_F(InscriptionTest, test_WithGoodJson)
{
    Common::Database::MockPostgresSQL* psql = new Common::Database::MockPostgresSQL();
    pqxx::result res;
    //pqxx::internal::gate::result_creation::create(res) cre;

    psql->setExpectedResult(res);

    server = new Mock::RestApiServer();

    inscription = new Inscription();
    inscription->setServer(server);

    Common::Network::Header h;
    std::string body = R"({
                            "nom" : "TOTO",
                            "prenom" : "TOTO",
                            "email" : "toto@gmail.com",
                            "phone" : "+24166895426",
                            "password" : "@1123Adbcd",
                            "contact" : "email",
                            "naissance" : "01-01-2001"
                            })";
    
    Common::Network::HttpRequest* req = new Common::Network::HttpRequest(std::move(h), std::move(body));

    auto resp = inscription->process(req);

    delete req;
}

}
}