#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <fstream>

using namespace std;

#define SIZE_ETHERNET 14
#define DNS_PORT 53

// make the custom header
string make_custom_header(int query_id) {
    time_t t = time(nullptr);
    tm* tm = localtime(&t);
    ostringstream oss;


    oss << setfill('0') 
        << setw(2) << tm->tm_hour
        << setw(2) << tm->tm_min
        << setw(2) << tm->tm_sec
        << setw(2) << query_id;

    return oss.str();
}

int make_udp_client_socket(struct sockaddr_in &serv_addr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    // create udp socket of

    memset(&serv_addr, 0, sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    // indicate IP v4 style of the server

    serv_addr.sin_port = htons(5555);
    //selected a random safe port number which we selected as 5555

    // set ip addrees for the server which will the device local ip address
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    return sock;
}

void send_only(int sock, const struct sockaddr_in &serv_addr,
               const u_char *data, size_t data_len) {

    if (data_len > 32) cout << "...";
    cout << "\n";

    // send to server
    ssize_t s = sendto(sock, reinterpret_cast<const char*>(data),
                       data_len,
                       0,
                       (const struct sockaddr*)&serv_addr,
                       sizeof(serv_addr));

    cout << "client: sent " << s << " bytes successfully\n";

}

string receive_response(int sock) {
    char buf[1024];

    // recieve from server
    ssize_t n = recv(sock, buf, sizeof(buf)-1, 0);
    if (n > 0) {
        buf[n] = '\0';
        return string(buf);
    }
    return "";
}

int main() {
    pcap_t *handle = pcap_open_offline("6.pcap", nullptr);

    struct pcap_pkthdr *header;
    const u_char *packet;

// dns_packet stores all the dns query packets
    vector<vector<u_char>> dns_packets;
    vector<int> dns_packet_lens;


    while (pcap_next_ex(handle, &header, &packet) >= 0) {
        const struct ip *ip_hdr = (struct ip *)(packet + SIZE_ETHERNET);
        // skip first 14 bytes of ETHERNET

        if (ip_hdr->ip_p != IPPROTO_UDP) continue;
        // Only continue if udp protocol

        // Skip the IP header which is in set of 32 bits
        int ip_len = ip_hdr->ip_hl * 4;
        const struct udphdr *udp_hdr = (struct udphdr *)(packet + SIZE_ETHERNET + ip_len);

        // If source or destination port is 53(dns port)
        if (ntohs(udp_hdr->uh_dport) == DNS_PORT || ntohs(udp_hdr->uh_sport) == DNS_PORT) {

            int orig_len = (int)header->caplen;
            dns_packets.emplace_back(packet, packet + orig_len);
            dns_packet_lens.push_back(orig_len);

            cout << "collected DNS packet #" << (dns_packets.size()-1)
                 << " orig_len=" << orig_len << "\n";
        }
    }

    //  close pcap handle
    pcap_close(handle);

    struct sockaddr_in serv_addr;
    int sock = make_udp_client_socket(serv_addr);

    ofstream csv("client_resolutions.csv", ios::app);
    csv << "Custom header value(HHMMSSID) ,Domain name,Resolved IP address\n";

    // Iterate through all the filtered dns query packets
    for (size_t i = 0; i < dns_packets.size(); ++i) {

        string new_header = make_custom_header((int)i);

        int orig_len = dns_packet_lens[i];
        int total_len = 8 + orig_len;

        vector<u_char> new_packet(total_len);

        // add the custom header before the packet
        memcpy(new_packet.data(), new_header.c_str(), 8);

        // then copy the remaining packet
        memcpy(new_packet.data() + 8, dns_packets[i].data(), orig_len);

        cout << "prepared send for query#" << i
             << " header=" << new_header
             << " total_len=" << total_len << "\n";

        // call the function to send the updated packet
        send_only(sock, serv_addr, new_packet.data(), new_packet.size());

        // call the function to recieve response
        string response = receive_response(sock);

        // print response and put it in csv file
        if (!response.empty()) {
        cout << "client got response: " << response << "\n";
        csv << response << "\n";
        }

    }

    return 0;
}