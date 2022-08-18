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
	char errors[PCAP_ERRBUF_SIZE]; // ������� ������ ��� ������
	pcap_t *pcapFile = pcap_open_offline(m_fileName.c_str(), errors); // ��������� ����
	if ( pcapFile == NULL ) 
	{
        printf("Error opening: %s\n", errors);
        return 1;
    }

	struct pcap_pkthdr header; // ��������� ������
	uint64_t packets = 0;

	while (pcap_next(pcapFile, &header)) // ��������� ������, ���� �� ������ �� ����� �����
    {
		++packets;
	}

	return packets;	
}


uint64_t PCAPReader::payloadSize() const
{
	char errors[PCAP_ERRBUF_SIZE]; // ������� ������ ��� ������
	pcap_t *pcapFile = pcap_open_offline(m_fileName.c_str(), errors); // ��������� ����
	if ( pcapFile == NULL ) 
	{
        printf("Error opening: %s\n", errors);
        return 1;
    }
	struct pcap_pkthdr header; // ��������� ������
	uint64_t size = 0;


	while (pcap_next(pcapFile, &header)) // ��������� ������, ���� �� ������ �� ����� �����
    {
		size += header.len;
	}
	
	return size;
}