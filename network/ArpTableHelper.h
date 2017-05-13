#pragma once

#include <map>
#include <string>

class ArpTableHelper
{
public:
    /**
    *get the arptable info
    */
    static std::map<std::string, std::string> GetArpTable(const unsigned int eth_index);
    /**
    *delete specify arp table
    */
    static bool DeleteArpTable(const unsigned int eth_index);
};