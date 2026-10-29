#include "../common/global_define.h"
#include "../common/eq_stream_factory.h"
#include "../common/eqemu_logsys.h"
#include "../common/opcodemgr.h"
#include "../common/path_manager.h"
#include "../common/platform.h"
#include "../common/rulesys.h"
#include "../loginserver/eq_crypto.h"
#include "../common/json/json.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>
#include <unordered_set>

EQEmuLogSys LogSys;
PathManager path;
TimeoutManager timeout_manager;
std::unordered_set<uint32> ipWhitelist;
std::mutex ipMutex;
bool bSkipFactoryAuth = true;

int main(int argc, char **argv) {
    // No credentials on the command line or in output. Fixed loopback endpoint.
    if (argc != 4) return 64;
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data)) return 70;
    RegisterExecutablePlatform(ExePlatformTests);
    LogSys.LoadLogSettingsDefaults();
    LogSys.SilenceConsoleLogging();
    Json::Value credentials;
    std::ifstream input(argv[1]);
    input >> credentials;
    std::string username=credentials["username"].asString();
    std::string password=std::string(argv[3])=="reject" ? "synthetic-reject-1" : credentials["password"].asString();
    if(username.empty() || username.size()>19 || password.empty() || password.size()>19) return 65;
    SOCKET fd=socket(AF_INET,SOCK_DGRAM,0);
    sockaddr_in local{}; local.sin_family=AF_INET; local.sin_addr.s_addr=inet_addr("127.0.0.1");
    if(bind(fd,reinterpret_cast<sockaddr*>(&local),sizeof(local))) return 71;
    unsigned long nonblock=1; ioctlsocket(fd,FIONBIO,&nonblock);
    sockaddr_in remote=local; remote.sin_port=htons(6000);
    OpcodeManager *ops=new RegularOpcodeManager;
    if(!ops->LoadOpcodes(argv[2])) return 66;
    {
        EQOldStream stream(remote,static_cast<int>(fd));
        stream.SetState(ESTABLISHED);
        stream.SetOpcodeManager(&ops);
        stream.SetStreamType(OldStream);
        // Server-side transport starts its outbound ARQ at zero and expects
        // the legacy client's first request at one.
        stream.SACK.dwARQ=1;
        stream.dwLastCACK=65535;
        EQApplicationPacket ready(OP_SessionReady,4);
        stream.QueuePacket(&ready);
        bool login_sent=false,accepted=false;
        auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(15);
        while(std::chrono::steady_clock::now()<deadline) {
            Timer::SetCurrentTime();
            stream.SendPacketQueue();
            unsigned char buffer[8192];
            int length=recv(fd,reinterpret_cast<char*>(buffer),sizeof(buffer),0);
            if(length>0) stream.ParceEQPacket(length,buffer);
            while(auto packet=stream.PopPacket()) {
                auto opcode=packet->GetOpcode();
                if(opcode==OP_SessionReady && !login_sent) {
                    unsigned char clear[40]{};
                    std::memcpy(clear,username.c_str(),username.size());
                    std::memcpy(clear+20,password.c_str(),password.size());
                    EQApplicationPacket login(OP_LoginPC,40);
                    EQCrypto crypto; crypto.DoEQEncrypt(clear,login.pBuffer,40);
                    stream.QueuePacket(&login); login_sent=true;
                } else if(opcode==OP_LoginAccepted) {
                    if(std::string(argv[3])=="reject") return 4;
                    accepted=true;
                    EQApplicationPacket list(OP_ServerListRequest,4); stream.QueuePacket(&list);
                } else if(opcode==OP_ClientError) {
                    delete packet;
                    if(std::string(argv[3])=="reject") {std::cout<<"WRONG_PASSWORD_REJECTED"<<std::endl;return 0;}
                    std::cerr<<"LOCAL_LOGIN_REJECTED"<<std::endl;return 5;
                } else if(opcode==OP_ServerListRequest && accepted) {
                    uint16 count=0;if(packet->size>=2)std::memcpy(&count,packet->pBuffer,2);
                    delete packet;
                    if(count!=1) return 6;
                    std::cout<<"LOCAL_LOGIN_AND_ONE_WORLD_VERIFIED"<<std::endl;return 0;
                }
                delete packet;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    closesocket(fd);delete ops;
    std::cerr<<"LOCAL_LOGIN_PROTOCOL_TIMEOUT"<<std::endl;return 2;
}
