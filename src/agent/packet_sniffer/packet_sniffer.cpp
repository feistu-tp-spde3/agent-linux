/***************************************************************************
 *   Copyright (C) 2010 by Peter Krejci,,,   *
 *   info@peterkrejci.sk   *
 *                                                                         *
 *   All rights reserved.                                                  *
 *                                                                         *
 *   Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: *
 *     * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer. *
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution. *
 *     * Neither the name of the <ORGANIZATION> nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission. *
 *                                                                         *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS   *
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT     *
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR *
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR *
 *   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, *
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,   *
 *   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR    *
 *   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF *
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING  *
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS    *
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.          *
 ***************************************************************************/
#include <iostream>
#include <iomanip>
#include <cstring>
#include <ctime>

using namespace std;

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdlib.h>

#include "packet_sniffer.h"

#include "../packetsensor.h"

#include "../exceptions/epcap_init_error.h"
#include "../exceptions/epcap_runtime_error.h"


#include "../config/config_hash.h"
#include "../config/config_remote.h"

using namespace config;

#ifdef DEBUG
#include "../debugger/debugger.h"
using namespace debugger;
#endif

namespace packet_sniffer
{

Packet_sniffer::Packet_sniffer(int conn_interval)
{
    // DELETE
    //db = dbase;

    m_config_remote = Config_remote();

    m_last_loop_timestamp = time(NULL);
    this->m_conn_interval = conn_interval;

    m_connections = NULL;
}


Packet_sniffer::~Packet_sniffer()
{
    if (m_connections != NULL)
        delete m_connections;
}

//---------private methods---------
void Packet_sniffer::save()
{
}


void Packet_sniffer::init_shared_mem_and_semaphores()
{
    //shared memory initialization (used for synchronization of sending
    //finished connection to collector)

    int shared_mem_id;
    key_t key;
    int res;

    key = SHARED_MEMORY_ID;

    res = sem_unlink("/SemWrite");
    cout << "Res unlink SemWrite: " << res << endl;

    res = sem_unlink("/SemRead");
    cout << "Res unlink SemRead: " << res << endl;

    res = sem_unlink("/SemCounter");
    cout << "Res unlink SemCounter: " << res << endl;

    shmctl(key, IPC_RMID, NULL); //if exists, delete old shared memory


    //1 byte of memory witch acces rights
    if ((shared_mem_id = shmget(key, 1, IPC_CREAT | 0666)) < 0)
        cout << "CHYBA PRI SHARED MEMORY" << endl;


    //attach shared memory to addres space of actual process to be able to set it
    m_shared_memory = (char*)shmat(shared_mem_id, NULL, 0);
    if (m_shared_memory == (char*) - 1)
        cout << "ERROR WHILE ATTACHING SHARED MEMORY" << endl;
    else {
        cout << "SHARED MEMORY SUCCESFULLY ATTACHED AND SET TO 0" << endl;
        *m_shared_memory = 0; //init value, number stores an info, how many threads
        //with SQLReader running is actually moving data to final folder
    }

    //semaphores initialization

    m_sem_write = sem_open("/SemWrite", O_CREAT, S_IRWXU, 1);
    if (m_sem_write == SEM_FAILED)
        cout << "Semafor Write init failed" << endl;
    else
        cout << "Semafor Write init OK." << endl;

    m_sem_read = sem_open("/SemRead", O_CREAT, S_IRWXU, 1);
    if (m_sem_read == SEM_FAILED)
        cout << "Semafor Read init failed" << endl;
    else
        cout << "Semafor Read init OK." << endl;

    m_sem_counter = sem_open("/SemCounter", O_CREAT, S_IRWXU, 1);
    if (m_sem_counter == SEM_FAILED)
        cout << "Semafor Counter init failed" << endl;
    else
        cout << "Semafor Counter init OK." << endl;


}

void* Packet_sniffer::collector_sender_thread(void* config_local)
{
    sem_t* sem_write, *sem_read;
    char* shared_memory;
    int shared_mem_id;
    key_t key;
    stringstream command;
    Config_local* config = (Config_local*)config_local;

    key = SHARED_MEMORY_ID;

    if ((shared_mem_id = shmget(key, 1, 0666)) < 0) 
    {
        cout << "SENDING THREAD INVALID SHARED DATA POINTER KEY" << endl;
        pthread_exit((void*) - 1);
    }

    shared_memory = (char*)shmat(shared_mem_id, NULL, 0);
    if (shared_memory == (char*) - 1) 
    {
        cout << "SENDING THREAD ERROR TO ACCES SHARED MEMORY" << endl;
        pthread_exit((void*) - 1);
    }


    sem_write = sem_open("/SemWrite", O_CREAT); //get semaphor reference into globa$
    if (sem_write == SEM_FAILED) 
    {
        cout << "SENDING THREAD ERROR OPENING WRITE SEMAFOR" << endl;
        pthread_exit((void*) - 1);
    }

    sem_read = sem_open("/SemRead", O_CREAT); // get ref. for counter semapho$
    if (sem_read == SEM_FAILED) 
    {
        cout << "SENDING THREAD ERROR OPENING READ SEMAFOR" << endl;
        pthread_exit((void*) - 1);
    }

    command << "java -jar " << config->get_collector_sender_path() << " "
            << config->get_collector_sender_conf();


    while (true) 
    {
        cout << "SENDING THREAD JAVA PROGRAMM" << endl;
        sem_wait(sem_write);
        sem_wait(sem_read);
        sem_post(sem_read);

        // here will be called JAVA Collector Sender
        //  cout << command.str() << endl;
        system(command.str().c_str());


        sem_post(sem_write);
        sleep(100);
    }
}

/**
 * static function for calling callback funtion
 * @param args last argument of pcap loop - in our case this object
 * @param header pcap header
 * @param packet pointer to the first byte of a chunk of data containing the entire packet
 */
void Packet_sniffer::got_packet_wrapper(u_char* args, const struct pcap_pkthdr* header, const u_char* packet)
{
    Packet_sniffer* p_sniffer = (Packet_sniffer*)args;
    p_sniffer->got_packet(header, packet);
}

/**
 * static function for creating configuration checking thread
 * @param pthis this object
 */
void* Packet_sniffer::thread_wrapper(void* pthis)
{
    Packet_sniffer* p_sniffer = (Packet_sniffer*)pthis;
    p_sniffer->periodic_check();
}

/**
 * callback function for captured packet
 * @param header pcap header
 * @param packet pointer to the first byte of a chunk of data containing the entire packet
 */
void Packet_sniffer::got_packet(const struct pcap_pkthdr* header, const u_char* packet)
{
    Packet* captured_packet = new Packet;

    //timestamp
    captured_packet->captured_timestamp = header->ts.tv_sec;
    captured_packet->captured_microseconds = header->ts.tv_usec;
    //length
    captured_packet->length = header->len;

    //ethernet

    //structs for packet capturing
    const struct sniff_ethernet* ethernet;

    //getting data from packet
    ethernet = (struct sniff_ethernet*)(packet);

    captured_packet->dest_mac = long(ethernet->dest_mac[ETHER_ADDR_LEN - 1]);
    captured_packet->source_mac = long(ethernet->source_mac[ETHER_ADDR_LEN - 1]);

    for (long i = ETHER_ADDR_LEN - 2, pov = 0x100; i >= 0; i--, pov *= 0x100) 
    {
        captured_packet->dest_mac += (long(ethernet->dest_mac[i]) * pov);
        captured_packet->source_mac += (long(ethernet->source_mac[i]) * pov);
    }

    //convert ether type
    int ether_type = ethernet->ether_type[0] * 0x100 + ethernet->ether_type[1];

    captured_packet->protocols.push_back(m_config_remote.get_protocol(ether_type));

    //some protocols dont use IP addressess and ports
    bool empty_values = false;

    if (m_config_remote.get_protocol(ether_type).ident == ETHERTYPE_IP) 
    {
        //IP addresses
        const struct sniff_ip* ip;
        int size_ip;

        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;

        //convert in_addr to integer (type long)
        captured_packet->source_ip = in_addr_to_number(ip->ip_src);
        captured_packet->dest_ip = in_addr_to_number(ip->ip_dst);

        //IP protocol type
        captured_packet->protocols.push_back(m_config_remote.get_protocol(ip->ip_p));

        //ports in TCP/UDP connections
        if (ip->ip_p == IPPROTO_TCP) 
        {
            const struct sniff_tcp* tcp;
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

            captured_packet->source_port = ntohs(tcp->tcp_sport);
            captured_packet->dest_port = ntohs(tcp->tcp_dport);
            captured_packet->tcp_flags = char(tcp->tcp_flags);
            captured_packet->tcp_sequence = long(tcp->tcp_seq);
        } 
        else if (ip->ip_p == IPPROTO_UDP) {
            const struct sniff_udp* udp;
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

            captured_packet->source_port = ntohs(udp->udp_sport);
            captured_packet->dest_port = ntohs(udp->udp_dport);
        } 
        else 
        {
            empty_values = true;
        }
    }
    else 
    {
        empty_values = true;
    }

    if (empty_values) 
    {
        //IP addresses and ports are empty
        captured_packet->dest_ip      = 0;
        captured_packet->source_ip    = 0;
        captured_packet->dest_port    = 0;
        captured_packet->source_port  = 0;
        captured_packet->tcp_flags    = 0;
        captured_packet->tcp_sequence = 0;
    }

    //add packet to connections
    m_connections->add_packet(captured_packet, packet);

    //check if connection interval is reached
    time_t act_time = time(NULL);
    if (act_time - m_last_loop_timestamp >= m_conn_interval) 
    {
        //config_remote.check_configuration();
        //DELETE
        // connections->save(db);
        m_connections->save();
        // cout << "-----------::::::::SAVING DB::::::::--------" << endl;
        m_last_loop_timestamp = time(NULL);
    }

    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    //~~~~~~~~~~~~~~~~temporary outputs~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    //~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#if 0
    if (captured_packet->tcp_flags == TCP_SYN) {
        //timestamps
        cout << "Captured timestamp: " << captured_packet->captured_timestamp << endl;
        cout << "Captured microseconds: " << captured_packet->captured_microseconds << endl;

        //mac addresses

        cout << hex;

        cout << "Destination mac: ";
        cout << captured_packet->dest_mac << endl;
        cout << "Source mac: ";
        cout << captured_packet->source_mac << endl;

        cout << dec;

        //ip addresses
        cout << "Destination IP: ";
        cout << captured_packet->dest_ip << endl;
        cout << "Source IP: ";
        cout << captured_packet->source_ip << endl;

        //ports
        cout << "Destination port: ";
        cout << captured_packet->dest_port << endl;
        cout << "Source port: ";
        cout << captured_packet->source_port << endl;

        //tcp flag
        cout << "TCP flags: ";
        cout << int(captured_packet->tcp_flags) << endl;

        //packet length
        cout << "Length: ";
        cout << captured_packet->length << endl;

        //protocols
        cout << "Protocols: " << endl;
        for (int i = 0; i < captured_packet->protocols.size(); i++) {
            cout << captured_packet->protocols[i].name << endl;
        }

        cout << "-----------------------------------" << endl;
    }
#endif
}

/**
 * converts in_addr type of ip address to integer (type long)
 * @param addr ip address
 * @return ip address as number
 */
long Packet_sniffer::in_addr_to_number(const in_addr& addr)
{
    unsigned char* ip_segments = (unsigned char*)&addr;
    long ip_address;

    ip_address = (long(ip_segments[0]) * 0x1000000) +
                 (long(ip_segments[1]) * 0x10000) +
                 (long(ip_segments[2]) * 0x100) +
                 long(ip_segments[3]);

    return ip_address;
}

/**
 * get and apply config rules
 */
void Packet_sniffer::apply_config_rules()
{
    m_config_remote.check_configuration();

    struct bpf_program fp;
    string expression = m_config_remote.get_expression();
    pcap_compile(m_handle, &fp, expression.c_str(), 0, 0);
    pcap_setfilter(m_handle, &fp);
}

//---------public methods---------
/**
 * check period and check remote configuration
 */
void Packet_sniffer::periodic_check()
{
    struct timespec timeOut, remains;

    timeOut.tv_sec = 0;
    timeOut.tv_nsec = m_conn_interval * NANO_SEC;

    for (;;) 
    {
        nanosleep(&timeOut, &remains);
        time_t act_time = time(NULL);
        if (act_time - m_last_loop_timestamp >= m_conn_interval) 
        {
            m_config_remote.check_configuration();
            m_last_loop_timestamp = time(NULL);
            apply_config_rules();
        }
    }
}

/**
 * start the whole process of packet applying config rules, packet capturing, saving etc.
 */
void Packet_sniffer::run(Config_hash& cfg_hash, Config_local config_local)
{
    // TODO DEBUG
    //prepare pcap
    char* dev, errbuf[PCAP_ERRBUF_SIZE];
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) 
    {
        *logger << errbuf << endl;
        throw exceptions::EPcap_init_error();
    }
#ifdef DEBUG
    Debugger() << "Device: " << dev << endl;
#endif

    //NOTE sniffing in not-promiscuit MODE, this value should be in config file
    m_handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf);
    if (m_handle == NULL) 
    {
        *logger << errbuf << endl;
        throw exceptions::EPcap_init_error();
    }

    // make sure we're capturing on an Ethernet device
    if (pcap_datalink(m_handle) != DLT_EN10MB) 
    {
        *logger << dev << " is not an Ethernet" << endl;
        throw exceptions::EPcap_init_error();
    }

    *logger << "Using ethernet device " <<  dev << endl;

    //get local IP address
    int soc;
    struct ifreq ifr;

    soc = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ioctl(soc, SIOCGIFADDR, &ifr);
    close(soc);

    *logger << "Listening on IP " << inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr) << endl;

    long local_ip = in_addr_to_number(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);

    m_config_remote.init(cfg_hash.get_hash(),  config_local.get_sensor_name(), local_ip, config_local.get_protocol_filename());
    m_connections = new Connections(m_config_remote.get_sensor_id(), config_local.get_tmp_dir(), config_local.get_final_dir());

    m_config_remote.set_protocols(config_local.get_protocol_filename());

    apply_config_rules();

    const u_char* packet;
    struct pcap_pkthdr header;

    cout << "sychro init" << endl;
    init_shared_mem_and_semaphores();
    cout << "synchro end" << endl;
    //run thread for remote configuration checking
    pthread_t thread, sender_thread;
    int t_return;
    t_return = pthread_create(&thread, NULL, &Packet_sniffer::thread_wrapper, (void*) this);

    //run thread which will send files to collector
    pthread_create(&sender_thread, NULL, Packet_sniffer::collector_sender_thread, (void*)&config_local);

    //let`s do the job
    pcap_loop(m_handle, PACKET_CNT, Packet_sniffer::got_packet_wrapper, (u_char*) this);

    pcap_close(m_handle);
}
}
