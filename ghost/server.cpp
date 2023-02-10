#include <boost/asio.hpp>
#include <cstdlib>
#include <iostream>

using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void start()
    {
        do_read();
    }
private:
    void do_read()
    {
        auto self(shared_from_this());
        socket_.async_read_some(
            boost::asio::buffer(data, max_length),
            [this, self](boost::system::error_code ec, std::size_t length) {
                std::cout << data;
                if (!ec) {
                    do_write(length);
                }
            }
        );
    }

    void do_write(std::size_t length)
    {
        auto self(shared_from_this());
        boost::asio::async_write(
            socket_, boost::asio::buffer(data, strlen(data)),
            [this, self](boost::system::error_code ec, std::size_t length) {
                if (!ec) {
                    do_read();
                }
            }
        );
    }
    tcp::socket socket_;
    enum { max_length = 1024 };
    char data[max_length];
};

class Server {
public:
    Server(boost::asio::io_service &io_service, short port)
        : acceptor(io_service, tcp::endpoint(tcp::v4(), port)),
          socket(io_service) { do_accept(); }
private:
    void do_accept()
    {
        acceptor.async_accept(socket, [this](boost::system::error_code ec){
            if (!ec) {
                std::make_shared<Session>(std::move(socket))->start();
            }

            do_accept();
        });
    }

    tcp::acceptor acceptor;
    tcp::socket socket;
};

int main(int argc, char **argv)
{
    try {
        if (argc != 2) {
            std::cerr << "usage: " << argv[0] << "<port>\n";
            return 1;
        }

        boost::asio::io_service io_service;

        Server s(io_service, std::atoi(argv[1]));

        io_service.run();
    } catch (std::exception &e){
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}