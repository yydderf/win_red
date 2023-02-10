#include <boost/asio.hpp>
#include <iostream>

using boost::asio::ip::tcp;

class Client {
public:
    Client(boost::asio::io_service &io_service, const std::string &url, const std::string &port)
        : resolver(io_service), socket(io_service)
    {
        tcp::resolver::query query(url, port);
        resolver.async_resolve(query, [this](boost::system::error_code ec
            tcp::resolver::iterator endpoint_iterator) 
        {
            if (!ec) {
                tcp::endpoint endpoint = *endpoint_iterator;
                socket.async_connect(endpoint,
                    [this](boost::system::error_code ec, endpoint_iterator++));
            }
        });
    }

private:
    tcp::resolver resolver;
    tcp::socket socket;
}

int main(int argc, char **argv)
{
    try {
        if (argc != 3) {
            std::cerr << "usage: " << argv[0] << "<address> <port>\n";
            return 1;
        }

        boost::asio::io_service io_serivce;
        Client c(io_service, argv[1], argv[2]);
        io_service.run();
    } catch (std::exception &e) {
        std::cout << "exception: " << e.what() << std::endl;
    }

    return 0;
}