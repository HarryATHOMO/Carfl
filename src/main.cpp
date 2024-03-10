#include <csignal>
#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <Common/Network/ServerSocket.h>
#include <Common/Network/Socket.h>
#include <Common/Network/Errors.h>
#include <Common/Logger/Logger.h>



using namespace std;


struct sig_context {
    int triggered = 0;
    int signum;
} sig_ctxt;

static void signal_handler(int signum)
{
    sig_ctxt.signum = signum;
    sig_ctxt.triggered = 1;
}

static int sigs_setup()
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    struct s_h {
        int s;
        void (*h)(int);
    } caught_sigs[] = {
        {SIGINT,    &signal_handler},
        {SIGALRM,   &signal_handler},
        {SIGTERM,   &signal_handler},
        {SIGSEGV,   &signal_handler},
        {SIGPIPE,   &signal_handler},
    };

    for (const auto& sh : caught_sigs) {
        sa.sa_handler = sh.h;
        if (sigaction(sh.s, &sa, NULL) == -1) {
            std::cout << "Failed to setup signal handler " << sh.s << std::endl;
            return -1;
        }
    }

    return 0;
}

void parseArgument(int argc, char** argv)
{
    (void)(argc);
    (void)(argv);
}

using namespace Common;
int main(int argc, char** argv)
{
    sigs_setup();


    std::string configurationFile = "configuration.json";
    if (argc >= 2)
    {
        configurationFile = argv[1];
    }

    Logger::Logger logger("Log.txt");
    //Logger 
    logger.run();


    parseArgument(argc, argv);

    
    std::thread th;
    std::shared_ptr<Network::IServerSocket> server = std::shared_ptr<Network::IServerSocket>(new Network::ServerSocket());
    std::atomic<bool> quit {false};

    if (server->start(8080, true, true))
    {        
        th  = std::thread([&server, &quit]() {
            while(!quit.load())
            {
                server->update();
                while (auto msg = server->poll())
                {
                    if (msg->is<Network::Messages::Connection>())
                    {
                        std::cout << "Connexion de [" << Network::GetAddress(msg->from) << ":" << Network::GetPort(msg->from) << "]" << std::endl;
                    }
                    else if (msg->is<Network::Messages::Disconnection>())
                    {
                        std::cout << "Deconnexion de [" << Network::GetAddress(msg->from) << ":" << Network::GetPort(msg->from) << "]" << std::endl;
                    }
                    else if (msg->is<Network::Messages::UserData>())
                    {
                        std::cout << "receive message" << std::endl;
                        auto userdata = msg->as<Network::Messages::UserData>();
                        server->sendToAll(userdata->data.data(), static_cast<unsigned int>(userdata->data.size()));
                    }
                }
            }
            server->stop();
        });
    }
    else
    {
        std::cout << "Erreur initialisation serveur : " << Network::Errors::Get();
        return -2;
    }

    while (1) 
    {

            //watchdog_activity_alive(main_wdg_cookie);

            if (sig_ctxt.triggered) {

                LOG_INFO("Caught Signal %d", sig_ctxt.signum);

                switch (sig_ctxt.signum) {
                case SIGALRM:
                    std::cout << "rebooting.." << std::endl;
                    //sh_reboot(10, "Reboot due to SIGALRM signal", true);
                    break;

                case SIGINT:
                case SIGTERM:
                    std::cout << "stopping.." << std::endl;
                    break;
                case SIGPIPE:
                    sig_ctxt.triggered = 0;
                    continue;
                    break;
                }
                break;
            }
    }

    logger.requestStop();

    LOG_INFO("Caught Signal %d", sig_ctxt.signum);

    quit.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    th.join();

    return 0;
}