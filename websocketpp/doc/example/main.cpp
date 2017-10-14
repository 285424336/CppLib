#include <iostream>  
#include <string>  
#include <sstream>  

#include <websocketpp/client_wrapper.h>  

int main(int argc, char **argv)
{
    WSClient client("ws://10.64.8.16/");

    client.connect();
    std::this_thread::sleep_for(std::chrono::seconds(1));
    client.send("{\"eventName\" : \"__join\",\"data\" : {\"playerName\" : \"your name\"}}");
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}