#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <cassert>
#include <exception>
#include <sstream>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/config.hpp>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <map>

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

struct User {
    std::string login;
    bool is_enter;
    int score = 0;
    //std::string password; TODO restore system
};

class MainGame;

class LocalDataBase {
public:
    friend class MainGame;
    static LocalDataBase &instanse() {
        static LocalDataBase inst;
        return inst;
    }

    /* token */
    std::string reg(const std::string& login) {
        for(auto & node : users){
            if (node.second.login == login)
                return ""; //exist non-token
        }
        auto uuid = boost::uuids::to_string(boost::uuids::random_generator()());
        users[uuid] = User{ login };
        return uuid;
    }
    
    bool checkOnline(const std::string& token) {
        auto user = getUser(token);
        if (!user.has_value())
            return false;
        return user.value()->is_enter;
    }

    bool enter(const std::string& token) {
        auto user = getUser(token);
        if (!user.has_value())
            return false;
        user.value()->is_enter = true;
    }

    LocalDataBase(LocalDataBase const&) = delete;
    void operator=(LocalDataBase const&) = delete;

private:
    std::optional<User*> getUser(const std::string& token) {
        auto val = users.find(token);
        if (val == users.end())
            return std::nullopt;
        return &val->second;
    }

    LocalDataBase() {}
    std::map <std::string, User> users;
};

struct Card {
    int id;
    int color;
    int shape;
    int fill;
    int count;
};

class MainGame {
public:
    static MainGame& instanse() {
        static MainGame inst;
        return inst;
    }

    MainGame(MainGame const&) = delete;
    void operator=(MainGame const&) = delete;

    boost::property_tree::ptree getJsonField() {
        boost::property_tree::ptree file;
        boost::property_tree::ptree field;

        for (auto& card : m_cards) {
            boost::property_tree::ptree child;
            child.put("id", card.id);
            child.put("color", card.color);
            child.put("shape", card.shape);
            child.put("fill", card.fill);
            child.put("count", card.count);

            field.push_back({"", child });
        }
        file.add_child("cards", field);

        return file;
    }

    /*Score || -1 false*/
    int pick(const std::string& token, const std::array<int, 3>& arr_ids) {
        std::array<Card, 3> cards;
        int i = 0;
        for (auto id : arr_ids) {
            auto opt = getCardById(id);
            if (!opt.has_value())
                throw false;
            cards[i] = opt.value();
            i++;
        }
        if (checkCards(cards)) {
            for (auto& card : cards)
                removeCard(card);
            auto score = toggleScoreByToken(token);
            if (score == -1)
                throw false;
            return score;
        }
        return -1;
    }

    void addRandom() {
        m_cards.push_back({ last_id++, rand()%3, rand() % 3, rand() % 3, rand() % 3 });
    }

    boost::property_tree::ptree getScoresJson() {
        boost::property_tree::ptree file;
        boost::property_tree::ptree list;
        for (auto& [uuid, user] : LocalDataBase::instanse().users) {
            boost::property_tree::ptree child;

            child.put("name", user.login);
            child.put("score", user.score);

            list.push_back({ "", child });
        }
        file.add_child("users", list);
        return file;
    }

private:
//Variables
    int last_id;
    std::vector<Card> m_cards;
//Methods
    void removeCard(const Card& card) {
        std::erase_if(m_cards, [&](const auto& card_elem) { return (card_elem.id == card.id); });
    }

    int toggleScoreByToken(const std::string& token) {
        auto user = LocalDataBase::instanse().getUser(token);
        if (!user.has_value())
            return -1;
        return ++user.value()->score;
    }

    std::optional<Card> getCardById(int id) {
        auto it = std::find_if(m_cards.begin(), m_cards.end(), [&](auto& card_elem) { return id == card_elem.id; });
        if(it == m_cards.end())
            return std::nullopt;
        else 
            return *it;
    }
    bool checkCards(const std::array<Card, 3> & cards) {
        return checkProperty({ cards[0].color, cards[1].color, cards[2].color }) &&
               checkProperty({ cards[0].fill, cards[1].fill, cards[2].fill }) &&
               checkProperty({ cards[0].count, cards[1].count, cards[2].count }) &&
               checkProperty({ cards[0].shape, cards[1].shape, cards[2].shape });
    }
    bool checkProperty(const std::array<int, 3> & val) {
        return
            (val[0] == val[1] && val[1] == val[2]) ||
            (val[0] != val[1] && val[1] != val[2] && val[0] != val[1]);
    }

    MainGame() : m_cards(0), last_id(1) {}
};

//------------------------------------------------------------------------------

// Return a reasonable mime type based on the extension of a file.
beast::string_view
mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))  return "text/html";
    if (iequals(ext, ".html")) return "text/html";
    if (iequals(ext, ".php"))  return "text/html";
    if (iequals(ext, ".css"))  return "text/css";
    if (iequals(ext, ".txt"))  return "text/plain";
    if (iequals(ext, ".js"))   return "application/javascript";
    if (iequals(ext, ".json")) return "application/json";
    if (iequals(ext, ".xml"))  return "application/xml";
    if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
    if (iequals(ext, ".flv"))  return "video/x-flv";
    if (iequals(ext, ".png"))  return "image/png";
    if (iequals(ext, ".jpe"))  return "image/jpeg";
    if (iequals(ext, ".jpeg")) return "image/jpeg";
    if (iequals(ext, ".jpg"))  return "image/jpeg";
    if (iequals(ext, ".gif"))  return "image/gif";
    if (iequals(ext, ".bmp"))  return "image/bmp";
    if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff")) return "image/tiff";
    if (iequals(ext, ".tif"))  return "image/tiff";
    if (iequals(ext, ".svg"))  return "image/svg+xml";
    if (iequals(ext, ".svgz")) return "image/svg+xml";
    return "application/text";
}

std::string handleRequest(const std::string& json,const std::string &target) {
    std::stringstream ss;
    ss << json;
    boost::property_tree::ptree node;
    boost::property_tree::ptree out_node;
    boost::property_tree::read_json(ss, node);
    bool is_error = false;

    if (target == "/user/register") {
        //PARSING
        std::string login;
        std::string password;
        try {
            login = node.get<std::string>("nickname");
            password = node.get<std::string>("password");
        } catch (...) { is_error = true; }

        // LOGIC
        if (!is_error) {
            auto token = LocalDataBase::instanse().reg(login);

            node.erase("password");
            node.put<std::string>("accessToken", token);

            out_node = node;
        }
    }

    if (target == "/set/enter") {
        //PARSING
        std::string token;
        bool is_entry;
        try {
            token = node.get<std::string>("accessToken");
            is_entry = LocalDataBase::instanse().enter(token);
        }
        catch (...) { is_error = true; }

        // LOGIC
        out_node.put<bool>("success", is_entry);
    }

    if (target == "/set/field") {
        //PARSING
        std::string token;
        try {
            token = node.get<std::string>("accessToken");
        } catch (...) {is_error = true; }

        // LOGIC
        if (!is_error) {
            if (!LocalDataBase::instanse().checkOnline(token))
                is_error = true;
            else
                out_node = MainGame::instanse().getJsonField();
        }
    }

    if (target == "/set/pick") {
        //PARSING
        std::string token;
        try {
            token = node.get<std::string>("accessToken");
            // LOGIC
            if (!is_error) {
                int count = 0;
                std::array<int, 3> set;
                BOOST_FOREACH(boost::property_tree::ptree::value_type & child, node.get_child("cards")) {
                    if (count == set.size()) 
                        throw false;

                    set[count] = child.second.get_value<int>();
                    count++;
                }
                auto score = MainGame::instanse().pick(token, set);
                if (score == -1)
                    out_node.put<bool>("isSet", false);
                else {
                    out_node.put<bool>("isSet", true);
                    out_node.put<int>("score", score);
                }
            }
        }
        catch (...) { is_error = true; }
    }

    if (target == "/set/add") {
        //PARSING
        std::string token;
        try {
            token = node.get<std::string>("accessToken");
        } catch (...) { is_error = true; }

        // LOGIC
        if (!is_error) {
            MainGame::instanse().addRandom();
            out_node.put("success",true);
        }
    }

    if (target == "/set/scores") {
        //PARSING
        std::string token;
        try {
            token = node.get<std::string>("accessToken");
        } catch (...) { is_error = true; }
        // LOGIC
        if (!is_error) 
            out_node = MainGame::instanse().getScoresJson();
    }

    out_node.put("exception", is_error);

    ss.str("");
    boost::property_tree::write_json(ss, out_node);
    //std::cout << ss.str();
    return ss.str();
}

template <class Body, class Allocator>
http::message_generator
handle_request(
    beast::string_view doc_root,
    http::request<Body, http::basic_fields<Allocator>>&& req)
{

    // Respond to GET request
    http::response<http::string_body> res{ http::status::ok, req.version() };
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = handleRequest(req.body(), req.target());
    res.prepare_payload();
    return res;
}

//------------------------------------------------------------------------------

// Report a failure
void
fail(beast::error_code ec, char const* what) {
    std::cerr << what << ": " << ec.message() << "\n";
}

// Handles an HTTP server connection
void
do_session(
    tcp::socket& socket,
    std::shared_ptr<std::string const> const& doc_root)
{
    beast::error_code ec;

    // This buffer is required to persist across reads
    beast::flat_buffer buffer;

    for (;;)
    {
        // Read a request
        http::request<http::string_body> req;
        http::read(socket, buffer, req, ec);
        if (ec == http::error::end_of_stream)
            break;
        if (ec)
            return fail(ec, "read");

        // Handle request
        http::message_generator msg =
            handle_request(*doc_root, std::move(req));

        // Determine if we should close the connection
        bool keep_alive = msg.keep_alive();

        // Send the response
        beast::write(socket, std::move(msg), ec);

        if (ec)
            return fail(ec, "write");
        if (!keep_alive)
        {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            break;
        }
    }

    // Send a TCP shutdown
    socket.shutdown(tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
}

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    try
    {
        // Check command line arguments.
        if (argc != 4)
        {
            std::cerr <<
                "Usage: http-server-sync <address> <port> <doc_root>\n" <<
                "Example:\n" <<
                "    http-server-sync 0.0.0.0 8080 .\n";
            return EXIT_FAILURE;
        }
        auto const address = net::ip::make_address(argv[1]);
        auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
        auto const doc_root = std::make_shared<std::string>(argv[3]);

        // The io_context is required for all I/O
        net::io_context ioc{ 1 };

        // The acceptor receives incoming connections
        tcp::acceptor acceptor{ ioc, {address, port} };
        for (;;)
        {
            // This will receive the new connection
            tcp::socket socket{ ioc };

            // Block until we get a connection
            acceptor.accept(socket);

            // Launch the session, transferring ownership of the socket
            std::thread{ std::bind(
                &do_session,
                std::move(socket),
                doc_root) }.detach();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}