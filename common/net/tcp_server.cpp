#include "tcp_server.h"
#include "../event/event_loop.h"
#include <stdexcept>

void on_close_tcp_server_handle(uv_handle_t* handle) {
	delete (uv_tcp_t *)handle;
}

EQ::Net::TCPServer::TCPServer()
{
	m_socket = nullptr;
}

EQ::Net::TCPServer::~TCPServer() {
	Close();
}

void EQ::Net::TCPServer::Listen(int port, bool ipv6, std::function<void(std::shared_ptr<TCPConnection>)> cb)
{
	if (ipv6) {
		Listen("::", port, ipv6, cb);
	}
	else {
		Listen("0.0.0.0", port, ipv6, cb);
	}
}

void EQ::Net::TCPServer::Listen(const std::string &addr, int port, bool ipv6, std::function<void(std::shared_ptr<TCPConnection>)> cb)
{
	if (m_socket) {
		throw std::runtime_error("TCP listener already open");
	}

	m_on_new_connection = cb;

	auto loop = EQ::EventLoop::Get().Handle();
	m_socket = new uv_tcp_t;
	memset(m_socket, 0, sizeof(uv_tcp_t));
	int result = uv_tcp_init(loop, m_socket);
	if (result < 0) {
		delete m_socket;
		m_socket = nullptr;
		throw std::runtime_error(std::string("TCP initialization failed: ") + uv_strerror(result));
	}
	auto require_success = [&](int code, const char *operation) {
		if (code < 0) {
			Close();
			throw std::runtime_error(std::string("TCP ") + operation + " failed for " + addr + ":" + std::to_string(port) + ": " + uv_strerror(code));
		}
	};

	sockaddr_storage iaddr;
	if (ipv6) {
		require_success(uv_ip6_addr(addr.c_str(), port, (sockaddr_in6*)&iaddr), "address parsing");
	}
	else {
		require_success(uv_ip4_addr(addr.c_str(), port, (sockaddr_in*)&iaddr), "address parsing");
	}

	require_success(uv_tcp_bind(m_socket, (sockaddr*)&iaddr, 0), "bind");
	m_socket->data = this;

	result = uv_listen((uv_stream_t*)m_socket, 128, [](uv_stream_t* server, int status) {
		if (status < 0) {
			return;
		}

		auto loop = EQ::EventLoop::Get().Handle();
		uv_tcp_t *client = new uv_tcp_t;
		memset(client, 0, sizeof(uv_tcp_t));
		if (uv_tcp_init(loop, client) < 0) {
			delete client;
			return;
		}

		if (uv_accept(server, (uv_stream_t*)client) < 0) {
			uv_close((uv_handle_t*)client, on_close_tcp_server_handle);
			return;
		}

		EQ::Net::TCPServer *s = (EQ::Net::TCPServer*)server->data;
		s->AddClient(client);
	});
	require_success(result, "listen");
}

void EQ::Net::TCPServer::Close()
{
	if (m_socket) {
		uv_close((uv_handle_t*)m_socket, on_close_tcp_server_handle);
		m_socket = nullptr;
	}
}

void EQ::Net::TCPServer::AddClient(uv_tcp_t *c)
{
	std::shared_ptr<TCPConnection> client(new TCPConnection(c));
	if (m_on_new_connection) {
		m_on_new_connection(client);
	}
}
