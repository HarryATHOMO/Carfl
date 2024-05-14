#include <csignal>
#include <iostream>
#include <cstring>
#include <thread>
#include <atomic>
#include <filesystem>
#include <Common/Logger/Logger.h>
#include <Common/Component/IComponentManager.h>
#include <Common/Component/ComponentManager.h>
#include "RestHandlerPackage.h"



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

std::string configurationFile = "";

void parseArgument(int argc, char** argv)
{
    if (argc >= 2)
    {
        configurationFile = argv[1];
    }
}

using namespace Common::Comp;

int main(int argc, char** argv)
{
    sigs_setup();

    parseArgument(argc, argv);

    Common::Logger::Logger*	logger = new Common::Logger::Logger();
    IComponentManager* compMngr = new ComponentManager();

    try
    {
        compMngr->addLocalRegistry();
        compMngr->setLocalApiRestHandlerPackage(new CarflowServer::RestHandlerPackage());
        compMngr->loadConfigurationFromFile(configurationFile);
        compMngr->run();
    }
    catch(boost::exception& e)
    {
        std::string info = boost::diagnostic_information(e);
        std::cout << info << std::endl;
        std::raise(SIGINT);
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
            case SIGSEGV:
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

    compMngr->stop();

    compMngr->saveConfigurationToFile("");

    delete compMngr;

    logger->requestStop();
    delete logger;
    /*
    quit.store(true);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    th.join();

    config.exportConfiguration();*/

    return 0;
}