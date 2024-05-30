#include <iostream>
#include <thread>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

using namespace std;

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

#define PORT "4433"
#define CERT_FILE "server2.crt"
#define KEY_FILE "server.key"

void initialize_winsock() {
	WSADATA wsadata;
	int result = WSAStartup(MAKEWORD(2, 2), &wsadata);
	if (result != 0) {
		cerr << "WSAStartup failed: " << result << endl;
		exit(EXIT_FAILURE);
	}
}

void cleanup_winsock() {
	WSACleanup();
}

void initialize_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	return ctx;
}

void configure_context(SSL_CTX* ctx) {
	SSL_CTX_set_ecdh_auto(ctx, 1);

	if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	if (SSL_CTX_load_verify_locations(ctx, "rootCA.pem", nullptr) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
	SSL_CTX_set_verify_depth(ctx, 4);
}

void handle_client(SSL* ssl) {
	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
	}
	else {
		cout << "SSL connection establised!" << endl;
		const char reply[] = "HTTP / 1.1 200 OK\r\nContent - Length: 12\r\n\r\nHello world";
		SSL_write(ssl, reply, strlen(reply));
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
}

void accept_client(SOCKET server_fd, SSL_CTX* ctx) {
	while (true) {
		struct sockaddr_in addr;
		int addrlen = sizeof(addr);
		SOCKET client_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
		if (client_fd == INVALID_SOCKET) {
			cerr << "accept failed: " << WSAGetLastError() << endl;
			continue;
		}

		SSL* ssl = SSL_new(ctx);
		SSL_set_fd(ssl, (int)client_fd);

		thread client_thread(handle_client, ssl);
		client_thread.detach();
	}
}

int main() {

	initialize_winsock();
	initialize_openssl();

	SSL_CTX* ctx = create_context();
	configure_context(ctx);

	struct addrinfo hints, * res;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int result = getaddrinfo(NULL, PORT, &hints, &res);
	if (result != 0) {
		cerr << "getaddrinfo failed: " << gai_strerror(result) << endl;
		exit(EXIT_FAILURE);
	}

	SOCKET server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (server_fd == INVALID_SOCKET) {
		cerr << "socket failed: " << WSAGetLastError() << endl;
		freeaddrinfo(res);
		exit(EXIT_FAILURE);
	}

	result = bind(server_fd, res->ai_addr, (int)res->ai_addrlen);
	if (result == SOCKET_ERROR) {
		cerr << "bind failed: " << WSAGetLastError() << endl;
		freeaddrinfo(res);
		closesocket(server_fd);
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(res);

	result = listen(server_fd, SOMAXCONN);
	if (result == SOCKET_ERROR) {
		cerr << "listen failed: " << WSAGetLastError() << endl;
		closesocket(server_fd);
		exit(EXIT_FAILURE);
	}

	cout << "Waiting for connections on port " << PORT << "..." << endl;

	accept_client(server_fd, ctx);

	closesocket(server_fd);
	SSL_CTX_free(ctx);
	cleanup_winsock();

	return 0;
}