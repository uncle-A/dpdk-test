#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#include "filter_rules.h"

#ifdef USE_PACKET_FILTER


/**
 * A simple server getting commands to setup packets filtering.
 * The command is a json arrays. See 'filter_riles.c'
*/

typedef struct filter_srv
{
	int			sock;
	int			cli_sock;
	int			port;
	int			enabled;
	uint32_t	recvbuf_size;
	char		*recvbuf;
} filter_srv_t;

static filter_srv_t filter_srv = {0};


/**
 * @brief the incoming connection preparation
 * @param port - port number for conversation
 * @return
 * - 0  - success
 * - -1 - error
 */
static int filter_conn_init(int port)
{
	int ret = 0;

	filter_srv.sock = -1;
	filter_srv.port = port;

	filter_srv.sock = socket(AF_INET, SOCK_STREAM, 0);
	if (filter_srv.sock == -1)
	{
		perror("filter: error socket creation");
		return -1;
	}

	struct sockaddr_in server = {0};
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(filter_srv.port);
	socklen_t size = (socklen_t)sizeof(server);

	ret = bind(filter_srv.sock, (struct sockaddr *)&server, size);
	if (ret == -1)
	{
		perror("filter: can't bind socket with port");
		filter_srv_stop();
		return -1;
	}

	int backlog = 20;
	ret = listen(filter_srv.sock, backlog);
	if (ret == -1)
	{
		perror("filter: can't listen socket");
		filter_srv_stop();
		return -1;
	}

	return 0;
}

/**
 * @brief helper to free buffer of incoming rules
 * @param size - new buffer size (0 - free)
 */
static void resize_recvbuf(uint32_t size)
{
	if (size == 0)
	{
		free(filter_srv.recvbuf);
		filter_srv.recvbuf = NULL;
		filter_srv.recvbuf_size = 0;
		return;
	}

	if (filter_srv.recvbuf_size != size)
	{
		filter_srv.recvbuf = realloc(filter_srv.recvbuf, size);
		filter_srv.recvbuf_size = size;
	}

	memset(filter_srv.recvbuf, 0, filter_srv.recvbuf_size);
}

/**
 * @brief processing received incoming data
 * @param sock - socket for receiving data from
 */
static void filter_recvd_processing(int sock)
{
	while(filter_srv.enabled)
	{
		int     flags = 0;
		int32_t buf_size = 4 * 1024;
		ssize_t remain = buf_size-1;
		ssize_t total = 0;

		resize_recvbuf(buf_size);

		char *pbuf = filter_srv.recvbuf;

		do
		{
			int gotbytes = recv(sock, pbuf, remain, flags);
			if (gotbytes == -1)
			{
				perror("filter: recv() error - skip processing");
				total = -1;
				break;
			}

			if (gotbytes == 0)
				break;

			total  += gotbytes;
			pbuf   += gotbytes;
			remain -= gotbytes;

		} while(total < buf_size);

		if (total == -1)
			break;

		filter_set(filter_srv.recvbuf, total);
		break;
	}

	shutdown(sock, SHUT_RDWR);
	close(sock);

	resize_recvbuf(0);

	RTE_LOG(INFO, USER1, "%s() done ok\n", __func__);
}

static void *filter_recv_thread(void *arg)
{
	(void)arg;

	while(filter_srv.enabled)
	{
		int accepted_socket = accept(filter_srv.sock, NULL, NULL);
		if (accepted_socket == -1)
		{
			perror("filter: can't accept incoming connection");
			continue;
		}

		RTE_LOG(DEBUG, USER1, "filter: accepted\n");
		filter_recvd_processing(accepted_socket);
	}

	RTE_LOG(INFO, USER1, "filter: server finished\n");
	return NULL;
}

int filter_srv_run(int port)
{
	if (filter_conn_init(port) == -1)
		return -1;

	filter_srv.enabled = 1;

	pthread_t thread_id;
	pthread_attr_t attr = {0};
	// pthread_attr_init(&attr);

	int ret = pthread_create(&thread_id, &attr, &filter_recv_thread, NULL);
	if (ret != 0)
	{
		perror("filter: pthread_create() failed");
		return -1;
	}

	RTE_LOG(INFO, USER1, "filter: start rules server at port %d\n", port);

	// ret = pthread_join(thread_id, NULL);
	ret = pthread_detach(thread_id);
	if (ret != 0)
	{
		perror("filter: pthread_detach() failed");
		return -1;
	}

	return 0;
}

/**
 * @brief destroy incoming connection object
 * @param filter_srv - incoming connection object
 */
void filter_srv_stop(void)
{
	filter_srv.enabled = 0;

	if (filter_srv.sock >= 0)
	{
		shutdown(filter_srv.sock, SHUT_RDWR);
		close(filter_srv.sock);
		filter_srv.sock = -1;
	}

	if (filter_srv.cli_sock >= 0)
	{
		close(filter_srv.cli_sock);
		filter_srv.cli_sock = -1;
	}

	resize_recvbuf(0);
}


#endif /* USE_PACKET_FILTER */
