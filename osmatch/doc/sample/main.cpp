// OsMatch.cpp : Defines the entry point for the console application.
//
#define WIN32_LEAN_AND_MEAN
#include "FingerPrintDB.h"
#if defined(_MSC_VER)
#include <file\FileHelper.h>
#include <string\StringHelper.h>
#include <network\NetworkHelper.h>
#include <network\ArpTableHelper.h>
#include <network\NetworkInfoHelper.h>
#include <socket\protocal\ICMPHelper.h>
#include <threadpool\ThreadPool.h>
#elif defined(__GNUC__)
#include <file/FileHelper.h>
#include <string/StringHelper.h>
#include <network/NetworkHelper.h>
#include <network/ArpTableHelper.h>
#include <network/NetworkInfoHelper.h>
#include <socket/protocal/ICMPHelper.h>
#include <threadpool/ThreadPool.h>
#else
#error unsupported compiler
#endif

#include "OsScanTask.h"
#include "SyncScanTask.h"
#include <iostream>

static int addtochararrayifnew(const char *arr[], int *numentries, int arrsize,
    const char *candidate)
{
    int i;

    // First lets see if the member already exists
    for (i = 0; i < *numentries; i++) {
        if (strcmp(arr[i], candidate) == 0)
            return *numentries;
    }

    // Not already there... do we have room for a new one?
    if (*numentries >= arrsize)
        return -1;

    // OK, not already there and we have room, so we'll add it.
    arr[*numentries] = candidate;
    (*numentries)++;
    return *numentries;
}

#define MAX_OS_CLASSMEMBERS 8
static void printosclassification(std::string &info, const OSClassificationResults *OSR, bool guess)
{
    int classno = 0, cpeno, familyno;
    unsigned int i;
    int overflow = 0;             /* Whether we have too many devices to list */
    const char *types[MAX_OS_CLASSMEMBERS];
    const char *cpes[MAX_OS_CLASSMEMBERS];
    char fullfamily[MAX_OS_CLASSMEMBERS][128];    // "[vendor] [os family]"
    double familyaccuracy[MAX_OS_CLASSMEMBERS];   // highest accuracy for this fullfamily
    char familygenerations[MAX_OS_CLASSMEMBERS][96];      // example: "4.X|5.X|6.X"
    int numtypes = 0, numcpes = 0, numfamilies = 0;
    char tmpbuf[1024];
    char info_buf[1024];

    for (i = 0; i < MAX_OS_CLASSMEMBERS; i++) {
        familygenerations[i][0] = '\0';
        familyaccuracy[i] = 0.0;
    }

    if (OSR->overall_results == OSSCAN_SUCCESS) {

        // Now to create the fodder for normal output
        for (auto it = OSR->osc.begin(); it != OSR->osc.end(); it++, classno++)
        {
            if ((!guess && classno >= OSR->osc_num_perfect_matches) ||
                it->first <= OSR->osc.begin()->first - 0.1 ||
                (it->first < 1.0 && classno > 9))
                break;
            if (addtochararrayifnew(types, &numtypes, MAX_OS_CLASSMEMBERS,
                it->second.Device_Type) == -1) {
                overflow = 1;
            }
            for (i = 0; i < it->second.cpe.size(); i++) {
                if (addtochararrayifnew(cpes, &numcpes, MAX_OS_CLASSMEMBERS,
                    it->second.cpe[i]) == -1) {
                    overflow = 1;
                }
            }

            // If family and vendor names are the same, no point being redundant
            if (strcmp(it->second.OS_Vendor, it->second.OS_Family) == 0) {
                snprintf(tmpbuf, sizeof(tmpbuf), "%s", it->second.OS_Family);
            }
            else {
                snprintf(tmpbuf, sizeof(tmpbuf), "%s %s", it->second.OS_Vendor, it->second.OS_Family);
            }


            // Let's see if it is already in the array
            for (familyno = 0; familyno < numfamilies; familyno++) {
                if (strcmp(fullfamily[familyno], tmpbuf) == 0) {
                    // got a match ... do we need to add the generation?
                    if (it->second.OS_Generation
                        && !strstr(familygenerations[familyno],
                            it->second.OS_Generation)) {
                        int flen = strlen(familygenerations[familyno]);
                        // We add it, preceded by | if something is already there
                        if (flen + 2 + strlen(it->second.OS_Generation) >= sizeof(familygenerations[familyno]))
                            return;
                        if (*familygenerations[familyno])
                            strcat(familygenerations[familyno], "|");
                        strncat(familygenerations[familyno],
                            it->second.OS_Generation,
                            sizeof(familygenerations[familyno]) - flen - 1);
                    }
                    break;
                }
            }

            if (familyno == numfamilies) {
                // Looks like the new family is not in the list yet.  Do we have room to add it?
                if (numfamilies >= MAX_OS_CLASSMEMBERS) {
                    overflow = 1;
                    break;
                }
                // Have space, time to add...
                snprintf(fullfamily[numfamilies], 128, "%s", tmpbuf);
                if (it->second.OS_Generation) {
                    snprintf(familygenerations[numfamilies], 48, "%s", it->second.OS_Generation);
                }
                familyaccuracy[numfamilies] = it->first;
                numfamilies++;
            }
        }

        if (!overflow && numfamilies >= 1) {
            snprintf(info_buf, sizeof(info_buf), "Device type: ");
            info += info_buf;
            for (classno = 0; classno < numtypes; classno++)
            {
                snprintf(info_buf, sizeof(info_buf), "%s%s", types[classno], (classno < numtypes - 1) ? "|" : "");
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\nRunning%s: ", OSR->osc_num_perfect_matches == 0 ? " (JUST GUESSING)" : "");
            info += info_buf;
            for (familyno = 0; familyno < numfamilies; familyno++) {
                if (familyno > 0)
                {
                    snprintf(info_buf, sizeof(info_buf), ", ");
                    info += info_buf;
                }
                snprintf(info_buf, sizeof(info_buf), "%s", fullfamily[familyno]);
                info += info_buf;
                if (*familygenerations[familyno])
                {
                    snprintf(info_buf, sizeof(info_buf), " %s", familygenerations[familyno]);
                    info += info_buf;
                }
                if (familyno >= OSR->osc_num_perfect_matches)
                {
                    snprintf(info_buf, sizeof(info_buf), " (%.f%%)", floor(familyaccuracy[familyno] * 100));
                    info += info_buf;
                }
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;

            if (numcpes > 0) {
                snprintf(info_buf, sizeof(info_buf), "OS CPE:");
                info += info_buf;
                for (cpeno = 0; cpeno < numcpes; cpeno++)
                {
                    snprintf(info_buf, sizeof(info_buf), " %s", cpes[cpeno]);
                    info += info_buf;
                }
                snprintf(info_buf, sizeof(info_buf), "\n");
                info += info_buf;
            }
        }
    }
    return;
}

void printosscan(std::string &info, FingerPrintResults *FPR) {
    int i;
    char info_buf[1024];

    // If the FP can't be submitted anyway, might as well make a guess.
    printosclassification(info, &FPR->GetOSClassification(), false); 

    if (FPR->overall_results == OSSCAN_SUCCESS && FPR->num_perfect_matches <= 8) {
        /* Success, not too many perfect matches. */
        if (FPR->num_perfect_matches > 0) {

            snprintf(info_buf, sizeof(info_buf), "OS: %s", FPR->matches[0].second->os_name);
            info += info_buf;
            for (i = 1; i < FPR->num_perfect_matches; i++)
            {
                snprintf(info_buf, sizeof(info_buf), "|%s", FPR->matches[i].second->os_name);
                info += info_buf;
            }

            snprintf(info_buf, sizeof(info_buf), "\nOS details: %s", FPR->matches[0].second->os_name);
            info += info_buf;
            for (i = 1; i < FPR->num_perfect_matches; i++) {
                snprintf(info_buf, sizeof(info_buf), ", %s", FPR->matches[i].second->os_name);
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;
        }
        else {

            /* Print the best guesses available */
            snprintf(info_buf, sizeof(info_buf), "Aggressive OS guesses: %s (%.f%%)", FPR->matches[0].second->os_name, floor(FPR->matches[0].first * 100));
            info += info_buf;
            for (i = 1; i < 10 && (int)FPR->matches.size() > i && FPR->matches[i].first > FPR->matches[0].first - 0.10; i++)
            {
                snprintf(info_buf, sizeof(info_buf), ", %s (%.f%%)", FPR->matches[i].second->os_name, floor(FPR->matches[i].first * 100));
                info += info_buf;
            }
            snprintf(info_buf, sizeof(info_buf), "\n");
            info += info_buf;
        }
    }
}

std::map<std::string, std::string> GetAllDevices(int total_second = 10, int one_wait_milliseconds = 1000)
{
    NetworkInfoHelper::NetworkInfo network_info = NetworkInfoHelper::GetInstance().GetNetworkInfo();
    std::set<std::string> ip_list = NetworkHelper::GetNetIPs(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address), NetworkHelper::IPStr2Addr(network_info.adapt_info.subnet_ip_mask));

    ArpTableHelper::DeleteArpTable(network_info.adapt_info.index);
    for (int i = 0; i < (total_second * 1000 / one_wait_milliseconds); i++)
    {
        auto send_thread = new std::thread([network_info, ip_list]
        {
            ICMPHelper icmp(NetworkHelper::IPStr2Addr(network_info.adapt_info.local_ip_address).s_addr);
            if (!icmp.Init()) return;
            for (auto device : ip_list)
            {
                icmp.SendICMPPingRequest(device);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
        send_thread->detach();
        std::this_thread::sleep_for(std::chrono::milliseconds(one_wait_milliseconds));
    }
    auto result = ArpTableHelper::GetArpTable(network_info.adapt_info.index);
    result[network_info.adapt_info.local_ip_address] = network_info.adapt_info.local_mac_address;
    return result;
}

using namespace TCPScan;
int main()
{
    std::string file;
    std::string dir;
    FileHelper::GetModulePath(file, dir);
    OsScanTask::InitFPDB(dir + "\\nmap-os-db");
    NetworkInfoHelper::NetworkInfo network_info = NetworkInfoHelper::GetInstance().GetNetworkInfo();
    auto devices = GetAllDevices(10, 1000);
    std::mutex out_mutex;

    std::vector<unsigned short> ports;
    unsigned short pop_ports[] = {
        80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
        143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
        1025, 587, 8888, 199, 1720,
        113, 554, 256
    };
    for (int i = 0; i < sizeof(pop_ports)/sizeof(*pop_ports); i++) {
        ports.emplace_back(pop_ports[i]);
    }
    std::sort(ports.begin(), ports.end());
    ThreadPool pool(20);

    while (1)
    {
        for (auto device : devices)
        {
            pool.enqueue([device, &out_mutex, &network_info, &ports] {
                char src_mac[6] = { 0 };
                char dst_mac[6] = { 0 };
                StringHelper::hex2byte(StringHelper::replace(device.second, ":", ""), (char *)dst_mac, 6);
                StringHelper::hex2byte(StringHelper::replace(network_info.adapt_info.local_mac_address, ":", ""), (char *)src_mac, 6);
                SyncScanTask port_task(ports, network_info.adapt_info.local_ip_address_int.s_addr, NetworkHelper::IPStr2Addr(device.first).s_addr
                    , src_mac, dst_mac, 6 * 1000);
                PortList list;
                port_task.DoScan(list);
                int closed_tcp_port = (AlgorithmHelper::GetRandomU32() % 14781) + 30000;
                int closed_udp_port = (AlgorithmHelper::GetRandomU32() % 14781) + 30000;
                int open_tcp_port = -1;
                Port port;
                if (list.NextPort(port, NULL, IPPROTO_TCP, PORT_CLOSED)) {
                    closed_tcp_port = port.port();
                }
                if (list.NextPort(port, NULL, IPPROTO_TCP, PORT_OPEN)) {
                    open_tcp_port = port.port();
                }
                Target t;
                t.closed_tcp_port = closed_tcp_port;
                t.closed_udp_port = closed_udp_port;
                t.open_tcp_port = open_tcp_port;
                t.is_direct = 1;
                t.dst_ip = NetworkHelper::IPStr2Addr(device.first).s_addr;
                StringHelper::hex2byte(StringHelper::replace(device.second, ":", ""), (char *)t.dst_mac, 6);
                t.src_ip = network_info.adapt_info.local_ip_address_int.s_addr;
                StringHelper::hex2byte(StringHelper::replace(network_info.adapt_info.local_mac_address, ":", ""), (char *)t.src_mac, 6);
                FingerPrintResults result;
                OsScanTask task(t);
                task.OsScan(result);
                std::string info;
                printosscan(info, &result);
                {
                    std::unique_lock<std::mutex> lock(out_mutex);
                    std::cout << "ip: " << device.first << " mac: " << device.second << std::endl;
                    std::cout << "using closed_tcp_port: " << closed_tcp_port << std::endl;
                    std::cout << "using closed_udp_port: " << closed_udp_port << std::endl;
                    std::cout << "using open_tcp_port: " << open_tcp_port << std::endl;
                    if (!info.empty()) {
                        std::cout << "info: " << info << std::endl;
                    }
                    else {
                        std::cout << "info: " << std::endl << std::endl;
                    }
                }
            });
        }
        std::cout << "next round" << std::endl;
        Sleep(60 * 1000);
    }
    return 0;
}

