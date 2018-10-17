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
#define BUFSIZE 2048
HCRYPTPROV ServerRSAProv;
HCRYPTKEY ServerRSAKeys;
enum CMD
{
	CMD_PUBKEY = 1,
	CMD_SESSIONKEY,
	CMD_VERIFY,
	CMD_TEST
};
struct client_ctx
{
	int socket;
	CHAR buf_recv[BUFSIZE]; // Буфер приема
	CHAR buf_send[BUFSIZE]; // Буфер отправки
	unsigned int current_read=0;
	unsigned int current_write=0;
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
						  // Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv
	bool sessionkeyenum = false;
	HCRYPTKEY ClientRSAKeys=NULL;
	HCRYPTKEY hSessionKey_AESClient=NULL;
	BYTE *ClientPublicKeyBlob = NULL;
	DWORD ClientPublicKeyBlobLength=0;
	BYTE *ClientSessionKeyBlob = NULL;
	DWORD ClientSessionKeyBlobLength = 0;


};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;
DWORD transferred;
ULONG_PTR key;
OVERLAPPED* lp_overlap;
// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv;
	buf.len = BUFSIZE;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}
// 

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
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
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}
// Функция стартует операцию приема соединения
void schedule_accept()
{
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED); // Создание сокета для принятия подключения (AcceptEx не создает сокетов)

	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
}
void encrypt_buf(DWORD idx, CHAR* buf, unsigned int *len)
{
	DWORD length = BUFSIZE;
	if (!CryptEncrypt(g_ctxs[idx].hSessionKey_AESClient, NULL, TRUE, 0, (BYTE*)buf, (DWORD*)len, length))
	{
		printf("Error during CryptEncrypt(). 0x%08x\n", GetLastError());
	}
}
void decrypt_buf(DWORD idx, CHAR* buf, unsigned int *len)
{
	DWORD length = *len;
	CryptDecrypt(g_ctxs[idx].hSessionKey_AESClient, NULL, TRUE, 0, (BYTE*)buf, (DWORD*)len);

}
void process_transmit(DWORD idx, CMD cmd, CHAR* buf, unsigned int len)
{
	unsigned int payloadlen = 0;
	g_ctxs[idx].buf_send[0] = cmd;
	payloadlen++;
	g_ctxs[idx].buf_send[1] = len << 0;
	payloadlen++;
	g_ctxs[idx].buf_send[2] = len << 8;
	payloadlen++;
	g_ctxs[idx].buf_send[3] = len << 16;
	payloadlen++;
	g_ctxs[idx].buf_send[4] = len << 24;
	payloadlen++;
	memcpy(g_ctxs[idx].buf_send + payloadlen, buf, len);
	payloadlen = payloadlen + len;

	//зашифровываем буфер для отправки
	if (g_ctxs[idx].sessionkeyenum == true)
	{
		encrypt_buf(idx, g_ctxs[idx].buf_send, &payloadlen);
		//decrypt_buf(idx, g_ctxs[idx].buf_send, &payloadlen);
	}

	WSABUF buffer;
	buffer.buf = g_ctxs[idx].buf_send;
	buffer.len = payloadlen;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buffer, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}
void process_recieve(DWORD idx, int* len)
{
	unsigned int tmplength = *len;
	//расшифровываем буфер для отправки
	if (g_ctxs[idx].sessionkeyenum == true)
	{
		decrypt_buf(idx,g_ctxs[idx].buf_recv, &tmplength);
	}
	CMD cmd=(CMD)g_ctxs[idx].buf_recv[0];
	uint32_t u0 = g_ctxs[idx].buf_recv[1], u1 = g_ctxs[idx].buf_recv[2], u2 = g_ctxs[idx].buf_recv[3], u3 = g_ctxs[idx].buf_recv[4];
	uint32_t length = (u0&(0xff)) | (u1&(0xff)) | (u2&(0xff)) | (u3&(0xff));
	switch (cmd)
	{
		case CMD_PUBKEY:
		{
			//полученная длина - длина публичного ключа клиента
			g_ctxs[idx].ClientPublicKeyBlobLength = length;
			//выделение памяти для блоба публичного ключа
			if ((g_ctxs[idx].ClientPublicKeyBlob = (BYTE *)malloc(g_ctxs[idx].ClientPublicKeyBlobLength)))
			{
				//копирование в полученный массив
				memcpy(g_ctxs[idx].ClientPublicKeyBlob, g_ctxs[idx].buf_recv + 5, length);
				//импорт ключа из массива
				if (CryptImportKey(ServerRSAProv, g_ctxs[idx].ClientPublicKeyBlob, g_ctxs[idx].ClientPublicKeyBlobLength, 0, CRYPT_EXPORTABLE, &g_ctxs[idx].ClientRSAKeys))
				{
					//генерация сессионного ключа для клиента
					if (CryptGenKey(ServerRSAProv, CALG_AES_256, CRYPT_EXPORTABLE, &g_ctxs[idx].hSessionKey_AESClient))
					{
						//экспорт ключа в массив - получение длины
						if (CryptExportKey(g_ctxs[idx].hSessionKey_AESClient, g_ctxs[idx].ClientRSAKeys, SIMPLEBLOB, 0, 0, &g_ctxs[idx].ClientSessionKeyBlobLength))
						{
							//выделение памяти для массива сессионного ключа
							if ((g_ctxs[idx].ClientSessionKeyBlob = (BYTE *)malloc(g_ctxs[idx].ClientSessionKeyBlobLength)))
							{
								//экспорт сессионного ключа в g_ctxs[idx].ClientSessionKeyBlob
								if (CryptExportKey(g_ctxs[idx].hSessionKey_AESClient, g_ctxs[idx].ClientRSAKeys, SIMPLEBLOB, 0, g_ctxs[idx].ClientSessionKeyBlob, &g_ctxs[idx].ClientSessionKeyBlobLength))
								{
									//отправка сессионного ключа
									process_transmit(idx, CMD_SESSIONKEY, (CHAR*)g_ctxs[idx].ClientSessionKeyBlob, g_ctxs[idx].ClientSessionKeyBlobLength);
									break;
								}
								else
								{
									printf("Error during CryptExportKey(). 0x%08x\n", GetLastError());
									break;
								}
							}
							else
							{
								printf("Out of memory. \n");
								break;
							}
						}
						else
						{
							printf("Error during CryptExportKey().  0x%08x\n", GetLastError());
							break;
						}
					}
					else
					{
						printf("Error during CryptGenKey().  0x%08x\n", GetLastError());
						break;
					}
				}
				else
				{
					printf("\nError during CryptImportKey(). \n");
					break;
				}
			}
			else
			{
				printf("Out of memory. \n");
				break;
			}
			//генерация сессионного ключа
			break;
		}
		case CMD_VERIFY:
		{
			BYTE encryptedMessage[256];
			BYTE messageLen=length;
			string test= "Decryption Works -- using multiple blocks";
			DWORD encryptedMessageLen = messageLen;
			memcpy(encryptedMessage, g_ctxs[idx].buf_recv + 5, length);
			CryptDecrypt(g_ctxs[idx].hSessionKey_AESClient, NULL, TRUE, 0, encryptedMessage, &encryptedMessageLen);
			memset(encryptedMessage+ encryptedMessageLen,0, 256 - encryptedMessageLen);
			string str = string((char*)encryptedMessage);
			if (str == test)
			{
				g_ctxs[idx].sessionkeyenum = true;
				process_transmit(idx, CMD_TEST, (CHAR*)encryptedMessage, encryptedMessageLen);
			}
		}
		case CMD_TEST:
		{

		}
	}
}

void genkeys()
{
	//инициализация
	wchar_t info[] = L"Microsoft Enhanced RSA and AES Cryptographic Provider";
	if (!CryptAcquireContext(&ServerRSAProv, NULL, info, PROV_RSA_AES, 0))
	{
		if (NTE_BAD_KEYSET == GetLastError())
		{
			if (!CryptAcquireContext(&ServerRSAProv, NULL, info, PROV_RSA_AES, CRYPT_NEWKEYSET))
			{
				printf("Error in AcquireContext() 0x%08x\n", GetLastError());
			}
		}
		else
		{
			printf("Error in AcquireContext() 0x%08x\n", GetLastError());
		}
	}
	//генерация ключей
	if (!CryptGenKey(ServerRSAProv, CALG_RSA_KEYX, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &ServerRSAKeys))
	{
		printf("Error during CryptGenKey(). \n");
	}
	////экспорт публичного ключа в массив
	//if (!CryptExportKey(ServerRSAKeys, 0, PUBLICKEYBLOB, 0, NULL, &ClientPublicKeyBlobLength))
	//{
	//	printf("Error during CryptExportKey(). \n");
	//}
	//if (!(ClientPublicKeyBlob = (BYTE *)malloc(ClientPublicKeyBlobLength)))
	//{
	//	printf("Out of memory. \n");
	//}
	//if (!CryptExportKey(ServerRSAKeys, NULL, PUBLICKEYBLOB, NULL, ClientPublicKeyBlob, &ClientPublicKeyBlobLength))
	//{
	//	printf("Error during CryptExportKey(). \n");
	//}

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

	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);// Создание сокета прослушивания
	if (s == INVALID_SOCKET)
	{
		printf("Unable to create socket\n");
		WSACleanup();
		return SOCKET_ERROR;
	}

	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);// Создание порта завершения
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}

	memset(g_ctxs, 0, sizeof(g_ctxs));// Обнуление структуры данных для хранения входящих соединений
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9000);

	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return 0;
	}

	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0

	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}
	genkeys();
	g_ctxs[0].socket = s;

	schedule_accept();// Старт операции принятия подключения.

	while (1) // Бесконечный цикл принятия событий о завершенных операциях
	{

		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 10);// Ожидание событий в течение 1 секунды
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;

				add_accepted_connection(); // Принятие подключения и начало принятия следующего
				schedule_accept();
				schedule_read(key);
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;

					if (transferred == 0)// Данные приняты:
					{

					}
					g_ctxs[key].sz_recv = transferred;
					len = transferred;
					schedule_read(key);
					process_recieve(key, &len);
				}
				else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены

					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
				}
				else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
			//schedule_read(key);
		}
	}
}
int main()
{
	int error(0);
	io_serv();
	return 0;
}