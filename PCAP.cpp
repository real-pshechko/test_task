#include "PCAP.h"
#include <pcap.h>
#include <string>
#include <iostream>


PCAPReader::PCAPReader(const std::string &fileName) : m_fileName(fileName)
{
}


PCAPReader::~PCAPReader()
{
}

uint64_t PCAPReader::packetsCount() const
{
	char errors[PCAP_ERRBUF_SIZE]; // Создаем буффер для ошибок
	pcap_t *pcapFile = pcap_open_offline(m_fileName.c_str(), errors); // Открываем файл
	if ( pcapFile == NULL ) 
	{
        printf("Error opening: %s\n", errors);
        return 1;
    }

	struct pcap_pkthdr header; // Заголовок пакета
	uint64_t packets = 0;

	while (pcap_next(pcapFile, &header)) // Считываем пакеты, пока не дойдем до конца файла
    {
		++packets;
	}

	return packets;	
}


uint64_t PCAPReader::payloadSize() const
{
	char errors[PCAP_ERRBUF_SIZE]; // Создаем буффер для ошибок
	pcap_t *pcapFile = pcap_open_offline(m_fileName.c_str(), errors); // Открываем файл
	if ( pcapFile == NULL ) 
	{
        printf("Error opening: %s\n", errors);
        return 1;
    }
	struct pcap_pkthdr header; // Заголовок пакета
	uint64_t size = 0;


	while (pcap_next(pcapFile, &header)) // Считываем пакеты, пока не дойдем до конца файла
    {
		size += header.len;
	}
	
	return size;
}