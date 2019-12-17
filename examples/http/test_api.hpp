#ifndef TEST_API_H
#define TEST_API_H
#include "json.hpp"
#include "http_api_server.h"

using nlohmann::json;
class TestApi : public HttpApiServer
{
public:
    TestApi(const string& listen_address, uint16_t listen_port) :
        HttpApiServer(3, listen_address, listen_port)
    {
        m_resource["^/test_api$"][http::verb::get] = [this](HttpContext& cxt) {
            json res;
            res["error_code"] = 0;
            cxt.res.body() = res.dump();
        };
    }
};

#endif
