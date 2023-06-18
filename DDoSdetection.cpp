#include <iostream>
#include <algorithm>
#include <chrono>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <unordered_map>
#include <sstream>
#include <vector>

    const int Threshold = 100;
    const int Time_Window = 5;

    const int Syn_Flag = 1;
    const int Ack_Flag = 1 << 1;
    const int Psh_Flag = 1 << 2;
    const int Get_Request_Flag = 1 << 3;
    const int Post_Request_Flag = 1 << 4;

    struct TrafficData {
        int packetCount;
        std::chrono::time_point<std::chrono::system_clock> timestamp;
        std::string destIP;
        int destPort;
    };


    struct AttackInfo {
        int packetCount;
        std::string destIP;
        int destPort;
    };


    std::vector<std::string> split(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::stringstream ss(s);
        std::string token;
        while (getline(ss, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }


    bool isValidInteger(const std::string& s) {
        return !s.empty() && std::all_of(s.begin(), s.end(), ::isdigit);
    }


    std::string determineAttackType(const std::string& destIP, int destPort, int flags) {
        if (destPort == 80 && (flags & Get_Request_Flag)) {
            return "HTTP Flood";

        } else if (destPort == 80 && (flags & Post_Request_Flag)) {
            return "HTTP POST Flood";

        } else if (destPort == 443 && (flags & Get_Request_Flag)) {
            return "HTTPS Flood";

        } else if (destPort == 53) {
            return "DNS Amplification";

        } else if (destPort == 21 || destPort == 22 || destPort == 23) {
            return "SSH/FTP/Telnet Bruteforce";

        } else if (destPort == 3389) {
            return "RDP Bruteforce";

        } else if (flags & Syn_Flag) {
            return "SYN Flood";

        } else if ((flags & Ack_Flag) && (flags & Psh_Flag)) {
            return "ACK-PSH Flood";

        } else {
            return "Unknown attack";
            
        }
    }

    void processLine(const std::string& line, std::unordered_map<std::string, TrafficData>& trafficMap,
                    std::unordered_set<std::string>& detectedIPs,
                    std::unordered_map<std::string, AttackInfo>& attackInfoMap,
                    std::mutex& mutex, std::unordered_set<std::string>& printedIPs) {
        std::vector<std::string> fields = split(line, ',');

        std::string sourceIP = fields[11];
        std::string destIP = fields[12];


        int sourcePort = 0;
        int destPort = 0;
        int packetCount = 0;

        if (fields.size() >= 16) {
            try {
                if (!isValidInteger(fields[13]) || !isValidInteger(fields[14]) || !isValidInteger(fields[15])) {
                    throw std::invalid_argument("Invalid integer value");
                }
                sourcePort = std::stoi(fields[13]);
                destPort = std::stoi(fields[14]);
                packetCount = std::stoi(fields[15]);
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(mutex);
                return;
            }
        } else {
            std::lock_guard<std::mutex> lock(mutex);
            return;
        }


        std::string attackType = determineAttackType(destIP, destPort, packetCount);


        std::lock_guard<std::mutex> lock(mutex);
        trafficMap[sourceIP].packetCount += packetCount;
        trafficMap[sourceIP].timestamp = std::chrono::system_clock::now();
        trafficMap[sourceIP].destIP = destIP;
        trafficMap[sourceIP].destPort = destPort;


        if (trafficMap[sourceIP].packetCount > Threshold && detectedIPs.count(sourceIP) == 0) {
            detectedIPs.insert(sourceIP);

            AttackInfo attackInfo;
            attackInfo.packetCount = trafficMap[sourceIP].packetCount;
            attackInfo.destIP = trafficMap[sourceIP].destIP;
            attackInfo.destPort = trafficMap[sourceIP].destPort;

            attackInfoMap[sourceIP] = attackInfo;

            if (printedIPs.count(sourceIP) == 0) {
                std::cout << "Detected " << attackType << " from IP: " << sourceIP << std::endl;
                std::cout << "Destination IP: " << destIP << std::endl;
                std::cout << "Destination Port: " << destPort << std::endl;
                std::cout << "Packet Count: " << trafficMap[sourceIP].packetCount << std::endl;
            std::cout << "---------------------------------------------"<<std::endl;
            std::cout << ""<<std::endl;
            printedIPs.insert(sourceIP);
            }
        }

        auto currentTime = std::chrono::system_clock::now();
        for (auto it = trafficMap.begin(); it != trafficMap.end();) {
            if (std::chrono::duration_cast<std::chrono::seconds>(currentTime - it->second.timestamp).count() > Time_Window) {
                detectedIPs.erase(it->first);
                attackInfoMap.erase(it->first);
                it = trafficMap.erase(it);
            } else {
                ++it;
            }
        }
    }



int main() {

    std::unordered_map<std::string, TrafficData> trafficMap;
    std::unordered_set<std::string> detectedIPs;
    std::unordered_map<std::string, AttackInfo> attackInfoMap;
    std::unordered_set<std::string> printedIPs;
    std::mutex mutex;

    std::string line;
    while (getline(std::cin, line)) {
        std::thread t(processLine, line, std::ref(trafficMap), std::ref(detectedIPs),
                      std::ref(attackInfoMap), std::ref(mutex), std::ref(printedIPs));
        t.detach();
    }

    std::this_thread::sleep_for(std::chrono::seconds(Time_Window + 1));

    return 0;

}
