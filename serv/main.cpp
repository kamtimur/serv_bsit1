//#include <windows.h>
//#include <stdafx.h>
#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#include <iostream>
using namespace std;
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN
struct client_ctx
{
	int socket;
	CHAR buf_recv[512]; // ����� ������
	CHAR buf_send[512]; // ����� ��������
	unsigned int sz_recv; // ������� ������
	unsigned int sz_send_total; // ������ � ������ ��������
	unsigned int sz_send; // ������ ����������
						  // ��������� OVERLAPPED ��� ����������� � ����������
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // ����� ��� WSARecv
};
// �������������� ����� � ��� ������ ����������� ��������
// � ������� �������� (������ � overlapped � ��������)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;
DWORD transferred;
ULONG_PTR key;
OVERLAPPED* lp_overlap;
// ������� �������� �������� ������ �� ������
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;

	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// ������� �������� �������� �������� �������������� ������ � �����
void schedule_write(DWORD idx)//,char *b)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	//buf.buf = b;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;//strlen(buf.buf); 
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// ������� ��������� ����� �������� ����������� �������
void add_accepted_connection()
{
	DWORD i; // ����� ����� � ������� g_ctxs ��� ������� ������ �����������
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr, &remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// ����� ������ � ������ IOCP, � �������� key ������������ ������ �������
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// �������� ������ �� ������
			schedule_read(i);
			return;
		}
	}
	// ����� �� ������� => ��� �������� ��� �������� ����������
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}
// ������� �������� �������� ������ ����������
void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); // �������� ������ ��� �������� ����������� (AcceptEx �� ������� �������)

	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
	// �������� �����������.
	// ��� ������ �������� ����� ��������� - ���� ���������� ������� �����������. // ������� ������� ������ ���� �� 16 ���� ������ ������� ������ �������� ������������ ������������ ��
}
int is_string_received(DWORD idx, int* len)
{
	DWORD i;
	for (i = 0; i < g_ctxs[idx].sz_recv; i++)
	{
		if (g_ctxs[idx].buf_recv[i] == '\n')
		{
			*len = (int)(i + 1);
			return 1;
		}
	}
	if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
	{
		*len = sizeof(g_ctxs[idx].buf_recv);
		return 1;
	}
	return 0;
}
int io_serv()
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;

	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);// �������� ������ �������������
	if (s == INVALID_SOCKET)
	{
		printf("Unable to create socket\n");
		WSACleanup();
		return SOCKET_ERROR;
	}

	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);// �������� ����� ����������
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	memset(g_ctxs, 0, sizeof(g_ctxs));// ��������� ��������� ������ ��� �������� �������� ����������
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);

	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return 0;
	}

	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// ������������� ������������� ������ s � ����� io_port.
	// � �������� ����� ��� ��������������� ������ ������������ 0

	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	g_ctxs[0].socket = s;

	schedule_accept();// ����� �������� �������� �����������.

	while (1) // ����������� ���� �������� ������� � ����������� ���������
	{

		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 10);// �������� ������� � ������� 1 �������
		if (b)
		{
			// ��������� ����������� � ���������� ��������
			if (key == 0) // ���� 0 - ��� ��������������� ������
			{
				g_ctxs[0].sz_recv += transferred;

				add_accepted_connection(); // �������� ����������� � ������ �������� ����������
				schedule_accept();
			}
			else
			{
				// ����� ��������� ������� �� ���������� �������� �� �������. // ���� key - ������ � ������� g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;

					if (transferred == 0)// ������ �������:
					{
						//cout << "endconn" << endl;
						//CancelIo((HANDLE)g_ctxs[key].socket);// ���������� ���������
						//PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
						//continue;
					}
					g_ctxs[key].sz_recv += transferred;
					if (is_string_received(key, &len))
					{
						cout << g_ctxs[key].buf_recv << endl;
						//sprintf_s(g_ctxs[key].buf_send, "Test\0");
						//g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);
						//g_ctxs[key].sz_send = 0;
						//schedule_write(key);
						// ���� ������ ��������� ������, �� ������������ ����� � ������ ��� ����������
						//sprintf_s(g_ctxs[key].buf_send, "You string length: %d\0", len);
						//g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);
						//g_ctxs[key].sz_send = 0; schedule_write(key);

						//sprintf_s(g_ctxs[key].buf_send, "You string length: 45454\0", len);
						//g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);
						//g_ctxs[key].sz_send = 0; schedule_write(key);
					}
					else
					{
						// ����� - ���� ������ ������
						/*cout << "reading" << endl;*/
						schedule_read(key);
						cout << g_ctxs[key].buf_recv << endl;

					}
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// ������ ����������

					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// ���� ������ ���������� �� ��������� - ���������� ����������
						schedule_write(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// ��� ������������ ���������, ����� ����� ���� ������
					closesocket(g_ctxs[key].socket); memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// �� ����� �������� �� ���� ��������� � ������� ��������� �������, ��������� �����
			// ��������� �����-���� ������ ��������
			// ...
			//schedule_read(key);
		}
	}
}
int main()
{
	io_serv();
	return 0;
}