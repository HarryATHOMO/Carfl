#include <src/RestApiHandler/CodeAuthenticate.h>

namespace CarflowServer
{
namespace RestApiHandler
{
using namespace Common::Utils;
using namespace Common::Network;

HttpResponse CodeAuthentificate::process(Common::Network::HttpRequest*)
{
    return HttpResponse(ResponseCode::OK,"");
}
}
}