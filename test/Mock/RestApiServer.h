#include <Common/Network/RestApi/IServer.h>
#include <Common/UnitTest/Mock/Database/Mock_PostgresSQL.h>

namespace Test
{
namespace Mock
{
class RestApiServer : public Common::Network::RestApi::IServer
{
    Common::Database::MockPostgresSQL* psql = nullptr;
public:
    Common::Database::IDBInflux* getInfluxDb() override
    {
        return nullptr;
    }

    Common::Database::IPostgreSQL* getPSQL(uint8_t agentId) override
    {
        return psql;
    }

    bool sendTo(uint64_t clientid, const unsigned char* data, unsigned int len) override
    {
        return true;
    }

    bool sendToAll(const unsigned char* data, unsigned int len) override
    {
        return true;
    }

    void setPSQL(Common::Database::MockPostgresSQL* pq)
    {
        psql == pq;
    }
};
}
}