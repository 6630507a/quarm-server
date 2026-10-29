#include "../common/global_define.h"
#include "../common/eqemu_logsys.h"
#include "../common/eq_stream_factory.h"
#include "../common/event/event_loop.h"
#include "../common/net/tcp_server.h"
#include "../common/path_manager.h"
#include "../common/platform.h"
#include "../common/memory_mapped_file.h"
#include <cstring>
#include <chrono>
#include <iostream>
#include <thread>
#include <unordered_set>

EQEmuLogSys LogSys;
PathManager path;
TimeoutManager timeout_manager;
std::unordered_set<uint32> ipWhitelist;
std::mutex ipMutex;
bool bSkipFactoryAuth = true;

template <typename T>
bool open_udp(T &factory, unsigned long port, const std::string &address) {
    if constexpr (requires { factory.Open(port, address); }) {
        return factory.Open(port, address);
    } else {
        return factory.Open(port);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) return 64;
#ifdef _WINDOWS
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 70;
#endif
    RegisterExecutablePlatform(ExePlatformTests);
    LogSys.LoadLogSettingsDefaults();
    const int port = std::stoi(argv[3]);
    try {
        if (std::string(argv[1]) == "tcp-retry") {
            EQ::Net::TCPServer server;
            bool rejected=false;
            try { server.Listen("192.0.2.123",port,false,[](auto){}); }
            catch(const std::exception&) { rejected=true; }
            if(!rejected) return 4;
            EQ::EventLoop::Get().Process();
            for(int i=0;i<3;++i) {
                server.Listen(argv[2],port,false,[](auto){});
                server.Close();
                EQ::EventLoop::Get().Process();
            }
            std::cout<<"RETRY_VERIFIED"<<std::endl;
        } else if (std::string(argv[1]) == "udp-retry") {
            EQStreamFactory server(OldStream,port);
            if(open_udp(server,port,"192.0.2.123")) return 4;
            for(int i=0;i<3;++i) {
                if(!open_udp(server,port,argv[2])) return 5;
                server.Close();
            }
            std::cout<<"RETRY_VERIFIED"<<std::endl;
        } else if (std::string(argv[1]) == "mmf") {
            {
                EQ::MemoryMappedFile file(argv[2], 512);
                file.ZeroFile();
                std::memcpy(file.Get(), "mapping-sentinel", 17);
            }
            EQ::MemoryMappedFile reopened(argv[2]);
            if (reopened.Size() != 512 || std::memcmp(reopened.Get(), "mapping-sentinel", 17)) return 3;
            std::cout << "MAPPING_VERIFIED" << std::endl;
        } else if (std::string(argv[1]) == "tcp") {
            EQ::Net::TCPServer server;
            server.Listen(argv[2], port, false, [](auto) {});
            std::cout << "READY" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            server.Close();
            EQ::EventLoop::Get().Process();
        } else {
            EQStreamFactory server(OldStream, port);
            if (!open_udp(server, port, argv[2])) return 2;
            std::cout << "READY" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(3));
            server.Close();
        }
    } catch (const std::exception &error) {
        std::cerr << error.what() << std::endl;
        return 2;
    }
    return 0;
}
