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
#ifndef PACKET_SNIFFERPACKET_SNIFFER_H
#define PACKET_SNIFFERPACKET_SNIFFER_H

#include <pcap.h>
#include <net/ethernet.h> //ethernet constants
#include <arpa/inet.h> //in_addr
#include <ctime> //time_t, time()
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "connections.h"

#include "../config/config_hash.h"
#include "../config/config_local.h"
#include "../config/config_remote.h"

using namespace config;

namespace packet_sniffer 
{
    
    #define NANO_SEC 1000000000
    #define SHARED_MEMORY_ID 2016
    
    /**
     * structs helping to parse packet data
     * (source: http://tcpdump.org)
     */
    // Ethernet header
    struct sniff_ethernet 
    {
        u_char  dest_mac[ETHER_ADDR_LEN];
        u_char  source_mac[ETHER_ADDR_LEN];
        u_char  ether_type[2];                     /* IP? ARP? RARP? etc */
    };
    
    /* IP header */
    struct sniff_ip 
    {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
    };
    
    #define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
    #define IP_V(ip)        (((ip)->ip_vhl) >> 4)
    
    struct sniff_tcp 
    {
        u_short tcp_sport;               /* source port */
        u_short tcp_dport;               /* destination port */
        u_int   tcp_seq;                 /* sequence number */
        u_int   tcp_ack;                 /* acknowledgement number */
        u_char  tcp_offx2;               /* data offset, rsvd */
        #define TCP_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  tcp_flags;
        #define TCP_FIN  0x01
        #define TCP_SYN  0x02
        #define TCP_RST  0x04
        #define TCP_PUSH 0x08
        #define TCP_ACK  0x10
        #define TCP_URG  0x20
        #define TCP_ECE  0x40
        #define TCP_CWR  0x80
        #define TCP_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short tcp_win;                 /* window */
        u_short tcp_sum;                 /* checksum */
        u_short tcp_urp;                 /* urgent pointer */
    };
    
    struct sniff_udp 
    {
        u_short udp_sport;              /*source port*/
        u_short udp_dport;              /*destination port*/
    };
    
    
    /**
     *  @author Peter Krejci,,, <krejci.peter@gmail.com>
     */
    class Packet_sniffer 
    {
    private:
        Config_remote m_config_remote;
        Connections *m_connections;
        int m_conn_interval;
        time_t m_last_loop_timestamp;
        pcap_t *m_handle;
        char *m_shared_memory;
        sem_t *m_sem_write, *m_sem_read, *m_sem_counter;

        void save();
        void init_shared_mem_and_semaphores();
        static void *collector_sender_thread(void *);
        static void got_packet_wrapper(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        static void *thread_wrapper(void *pthis);
        void got_packet(const struct pcap_pkthdr *header, const u_char *packet);
        long in_addr_to_number(const in_addr &addr);
        void apply_config_rules();
        
    public:
        Packet_sniffer(int m_conn_interval);
        
        ~Packet_sniffer();
        
        void periodic_check();
        void run(Config_hash &cfg_hash, Config_local config_local);
    };
}

#endif
