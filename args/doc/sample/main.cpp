#include "ArgvHelper.h"

#include <iostream>
using namespace std;

int main(int argc, char *argv[])
{
    try
    {
        //format args parse format
        ArgvHelper::parser a;
        a.set_program_name("ArgHelper");//just for useage info
        a.add<string>("host", 'h', "host name", true);
        a.add<int>("port", 'p', "port number", false, 80, ArgvHelper::range_reader<int>(1, 65535));
        a.add<string>("type", 't', "protocol type", false, "http", ArgvHelper::oneof_reader<string>("http", "https", "ssh", "ftp", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"));
        a.add<vector<string>>("args", 'a', "args", false, vector<string>() = { "1234","5678" }, ArgvHelper::contain_reader<vector<string>>());
        a.add<int>("count", 'c', "send count", false, 2);
        a.add("gzip", '\0', "gzip when transfer", true);
        a.footer("comment ...");//just for useage info

        a.parse_check(argc, argv);//check input and parse

        //get args in input
        cout << a.get<string>("type") << "://"
            << a.get<string>("host") << ":"
            << a.get<int>("port");

        vector<string> args = a.get<vector<string>>("args");
        if (args.size())
        {
            cout << "/?";
        }
        for (decltype(args.size()) i = 0; i < args.size(); i++)
        {
            cout << args[i];
            if (i != args.size() - 1)  cout << "&";
        }

        vector<string> others = a.rest();
        if (others.size())
        {
            cout << "#";
        }
        for (decltype(a.rest().size()) i = 0; i < a.rest().size(); i++)
        {
            cout << a.rest()[i];
            if (i != a.rest().size() - 1)  cout << "&";
        }
        cout << endl;
        if (a.exist("gzip")) cout << "use gzip" << endl;
        cout << "send count " << a.get<int>("count") << endl;
    }
    catch (ArgvHelper::cmdline_error &e)
    {
        cout << "internal error:" << e.what();
        exit(-1);
    }
    catch (...)
    {
        cout << "unknown error";
        exit(-1);
    }
    return 0;
}
