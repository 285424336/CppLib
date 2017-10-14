#ifndef WEBSOCKET_CLIENT_WRAPPER_H_INCLUDED  
#define WEBSOCKET_CLIENT_WRAPPER_H_INCLUDED  

#include <string>  
#include <cstdlib>  
#include <map>  
#include <string>  
#include <sstream> 

#define _WEBSOCKETPP_CPP11_RANDOM_DEVICE_
#define _WEBSOCKETPP_CPP11_TYPE_TRAITS_
#define ASIO_STANDALONE
#if defined(_MSC_VER)
#include <websocketpp\config\asio_no_tls_client.hpp>  
#include <websocketpp\client.hpp>  
#include <websocketpp\common\thread.hpp>  
#include <websocketpp\common\memory.hpp>  
#elif defined(__GNUC__)
#include <websocketpp/config/asio_no_tls_client.hpp>  
#include <websocketpp/client.hpp>  
#include <websocketpp/common/thread.hpp>  
#include <websocketpp/common/memory.hpp> 
#else
#error unsupported compiler
#endif
#ifdef _DEBUG
#include <iostream>  
#endif // _DEBUG

typedef websocketpp::client<websocketpp::config::asio_client> ws_client;
typedef websocketpp::connection_hdl ws_conn_hdl;

class WSClient : public ws_client
{
public:
    /**
    *invoke when connection open
    */
    virtual void on_open(ws_client *client, ws_conn_hdl hdl)
    {
#ifdef _DEBUG
        std::cout << "OPEN" << std::endl;
#endif
    }

    /**
    *invoke when connection failed
    */
    virtual void on_fail(ws_client *client, ws_conn_hdl hdl)
    {
#ifdef _DEBUG
        std::cout << "FAILED" << std::endl;
#endif
    }

    /**
    *invoke when connection close
    */
    virtual void on_close(ws_client *client, ws_conn_hdl hdl)
    {
#ifdef _DEBUG
        std::cout << "CLOSE" << std::endl;
#endif
    }

    /**
    *invoke when recv msg from server    
    */
    virtual void on_message(ws_conn_hdl hdl, ws_client::message_ptr msg)
    {
#ifdef _DEBUG
        if (msg->get_opcode() == websocketpp::frame::opcode::text) {
            std::cout << msg->get_payload() << std::endl;
        }
        else {
            std::cout << websocketpp::utility::to_hex(msg->get_payload()) << std::endl;
        }
#endif
    }

public:
    WSClient(const std::string &uri) : g_wsUri(uri)
    {
        ws_client::clear_access_channels(websocketpp::log::alevel::all);
        ws_client::clear_error_channels(websocketpp::log::elevel::all);
        ws_client::init_asio();
        ws_client::start_perpetual();
        g_threadWS = std::make_shared<std::thread>(&ws_client::run, this);
    }

    virtual ~WSClient()
    {
        ws_client::stop_perpetual();
        this->close(websocketpp::close::status::going_away);
        if (g_threadWS) {
            g_threadWS->join();
        }
    }

    /**
    *connect to the server
    */
    virtual bool connect() 
    {
        if (g_wsClientConnection) {
            this->close();
        }

        websocketpp::lib::error_code ec;
        g_wsClientConnection = ws_client::get_connection(g_wsUri, ec);
        if (ec) {
            return false;
        }

        g_wsClientConnection->set_open_handler(websocketpp::lib::bind(
            &WSClient::on_open,
            this,
            this,
            websocketpp::lib::placeholders::_1
        ));
        g_wsClientConnection->set_fail_handler(websocketpp::lib::bind(
            &WSClient::on_fail,
            this,
            this,
            websocketpp::lib::placeholders::_1
        ));
        g_wsClientConnection->set_close_handler(websocketpp::lib::bind(
            &WSClient::on_close,
            this,
            this,
            websocketpp::lib::placeholders::_1
        ));
        g_wsClientConnection->set_message_handler(websocketpp::lib::bind(
            &WSClient::on_message,
            this,
            websocketpp::lib::placeholders::_1,
            websocketpp::lib::placeholders::_2
        ));

        ws_client::connect(g_wsClientConnection);
        return true;
    }

    /**
    *close the connect with server
    *code(in): the type you want to close with server
    */
    virtual void close(int code = websocketpp::close::status::normal)
    {
        if (g_wsClientConnection) {
            if (g_wsClientConnection->get_state() == websocketpp::session::state::value::open)
            {
                websocketpp::lib::error_code ec;
                ws_client::close(g_wsClientConnection->get_handle(), code, "", ec);
            }
            g_wsClientConnection = NULL;
        }
    }

    /**
    *send data to server
    *msg(in): the msg you want to send to server
    */
    virtual bool send(std::string msg)
    {
        if (!is_connected()) {
            return false;
        }
        websocketpp::lib::error_code ec;
        ws_client::send(g_wsClientConnection->get_handle(), msg, websocketpp::frame::opcode::text, ec);
        return !ec;
    }

    /**
    *get the server uri
    */
    virtual std::string uri()
    {
        return g_wsUri;
    }

    /**
    *check if is success connected to server
    */
    virtual bool is_connected()
    {
        if (!g_wsClientConnection) {
            return false;
        }
        return g_wsClientConnection->get_state() == websocketpp::session::state::value::open;
    }

protected:
    std::string g_wsUri;
    std::shared_ptr<std::thread> g_threadWS;
    ws_client::connection_ptr g_wsClientConnection;
};

#endif
