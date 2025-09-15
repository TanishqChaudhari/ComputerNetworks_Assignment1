#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <iostream>

using namespace std;

constexpr int PORT = 5555;
// the port number of the server we used a random safe unused port

constexpr int SIZE_ETHERNET = 14;
// 14 bytes of ethernet


string calc_domain(const unsigned char* dns_ptr) {
    // dns domain start after 12 bytes
    size_t pos = 12;
    string domain;
    // read the number of L characters and then then next L to extract part of the domain also seperate it by a dot
    while (true) {
        unsigned char L = dns_ptr[pos++];
        if (L == 0) break;
        // seperate the domain subpart with a dot
        if (!domain.empty()) domain.push_back('.');

        domain.append(reinterpret_cast<const char*>(dns_ptr + pos), L);
        pos += L;
    }
    return domain.empty() ? "" : domain;
}

// Iterater in the custom packet till we reach dns payload in similar way as we iterated in Parse.cpp
string calc_dns_payload(const unsigned char* buf) {

    const unsigned char* pkt = buf + 8;
    const unsigned char* ip_ptr = pkt + SIZE_ETHERNET;

    unsigned char ihl_words = ip_ptr[0] & 0x0F;
    size_t ip_header_len = ihl_words * 4;

    const unsigned char* udp_ptr = ip_ptr + ip_header_len;
    const unsigned char* dns_ptr = udp_ptr + 8;

    return calc_domain(dns_ptr);
}

int main() {
    vector<string> IP_POOL = {
        "192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4","192.168.1.5",
        "192.168.1.6","192.168.1.7","192.168.1.8","192.168.1.9","192.168.1.10",
        "192.168.1.11","192.168.1.12","192.168.1.13","192.168.1.14","192.168.1.15"
    };

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    // create udp socket

    if (sock < 0) {
        cerr << "Socket creation error\n";
        return 1;
    }

    sockaddr_in serv{};
    serv.sin_family = AF_INET;
    serv.sin_port = htons(PORT);
    // set the server port to 5555

    serv.sin_addr.s_addr = INADDR_ANY;
    // Packet sent to any ip on this device/port will be intercepted on server

    // bind the socket
    if (::bind(sock, reinterpret_cast<sockaddr*>(&serv), sizeof(serv)) < 0) {
        cerr << "Bind error\n";
        close(sock);
        return 1;
    }

    cout << "Listening on UDP port- " << PORT << "\n";

    while (true) {

        unsigned char buf[65536];
        // use a large buffer to recieve the packet from client
        sockaddr_in cli{};
        socklen_t cli_len = sizeof(cli);

        // recieve from client
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&cli), &cli_len);

        if (n <= 0) continue;


        string header(reinterpret_cast<char*>(buf), 8);
        string domain = calc_dns_payload(buf);

        // extract the hour and id
        int hour = (header[0]-'0')*10 + (header[1]-'0');
        int id   = (header[6]-'0')*10 + (header[7]-'0');

        // filter query according to the rules
        int ip_pool_start = 0;
        if (hour >= 4 && hour <= 11) ip_pool_start = 0;
        else if (hour >= 12 && hour <= 19) ip_pool_start = 5;
        else ip_pool_start = 10;


        string chosen_ip = IP_POOL[ip_pool_start + (id % 5)];


        cout << "Received " << n
                  << " bytes | Query ID: " << id 
                  << " | Domain: " << domain
                  << " | Resolved IP: " << chosen_ip << "\n";


        string response = header  + "," +"www."+ domain + "," + chosen_ip;

        // send response back to the client
        sendto(sock, response.c_str(), response.size(), 0, (sockaddr*)&cli, cli_len);
    }

    // close the socket
    close(sock);
    return 0;
}
