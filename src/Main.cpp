#include "Sockets.hpp"
#include "TCP/Server.hpp"
#include "Messages.hpp"
#include "Errors.hpp"

#include <iostream>

int main(int argc, char **argv)
{
    int sock, ctxMethod, port;
    SSL_CTX *ctx;
    const char *certFile, *keyFile;

    if (argc != 2 && argc != 5)
    {
        printHeader(argv[0]);
        exit(0);
    }

    port = (atoi(argv[1]) > 0 && atoi(argv[1]) < 65535) ? atoi(argv[1]) : DEFAULT_PORT;
    ctxMethod = (argc >= 3) ? atoi(argv[2]) : 4; // SSLv2, SSLv3, SSLv2&3 or TLSv1
    ctx = initSSLContext(ctxMethod);             // load SSL library and dependances
    certFile = (argc >= 4) ? argv[3] : NULL;
    keyFile = (argc >= 5) ? argv[4] : NULL;

    loadCertificates(ctx, certFile, keyFile); // load certificats and keys

    sock = makeServerSocket(port); // make a classic server socket

    while (42)
    {
        struct sockaddr_in addr;
        SSL *ssl;
        SOCKLEN_T len = sizeof(addr);
        int client = accept(sock, (struct sockaddr *)&addr, &len); // accept connection of client
        printf("[+] Connection [%s:%d]\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);      // get new SSL state with context
        SSL_set_fd(ssl, client); // set traditionnal socket to SSL
        routine(ssl);            // apply routine to the socket's content
    }

    CLOSESOCKET(sock); // close socket
#ifdef _WIN32
    WSACleanup(); // Windows's Winsock clean
#endif
    SSL_CTX_free(ctx); // release SSL's context
    return 0;
}

int main()
{
	if (!Network::Start())
	{
		std::cout << "Erreur initialisation WinSock : " << Network::Errors::Get();
		return -1;
	}
	
	unsigned short port;
	std::cout << "Port ? ";
	std::cin >> port;

	Network::TCP::Server server;
	if (!server.start(port))
	{
		std::cout << "Erreur initialisation serveur : " << Network::Errors::Get();
		return -2;
	}

	while(1)
	{
		server.update();
		while (auto msg = server.poll())
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
				auto userdata = msg->as<Network::Messages::UserData>();
				server.sendToAll(userdata->data.data(), static_cast<unsigned int>(userdata->data.size()));
			}
		}
	}
	server.stop();
	Network::Release();
	return 0;
}