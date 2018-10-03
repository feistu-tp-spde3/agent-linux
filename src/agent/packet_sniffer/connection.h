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
#ifndef PACKET_SNIFFERCONNECTION_H
#define PACKET_SNIFFERCONNECTION_H

#include <stdio.h>
#include <vector>
#include <string>
#include <ctime>

#include "../packetsensor.h"
#include "../config/config_remote.h"
#include <sys/types.h>

using namespace std;

namespace packet_sniffer 
{
    
    
    /**
 * Represents packet
 */
struct Packet {
    std::vector<config::Protocol> protocols;
    int captured_timestamp;
    int captured_microseconds;
    uint source_ip;
    long source_mac;
    int source_port;
    uint dest_ip;
    long dest_mac;
    int dest_port;
    char tcp_flags;
    long tcp_sequence;
    int length;
};


struct dump_info {
    unsigned int id_connection;
};


/**
 * Represents packet dump
 */
struct Dump
{
    u_char *data = (u_char*)"";
    uint length = 0;
};


/**
 *          @author Peter Krejci,,, <krejci.peter@gmail.com>
 */
class Connection
{
#define NOT_DEFINED -1
#define EMPTY_CONNECTION -2

private:
    int m_id_connection;
    int m_id_sensor;
    vector<Packet> m_packets;
    vector<Packet> m_temp_packets;
    Dump m_first_dump;                  // later used for hash generation
    vector<Dump> m_dumps;
    vector<Dump> m_temp_dumps;
    uint m_ip_source_machine;
    uint m_ip_dest_machine;
    long m_mac_source_machine;
    long m_mac_dest_machine;
    int m_port_source_machine;
    int m_port_dest_machine;
    int m_start_timestamp;
    int m_start_microseconds;
    int m_finish_timestamp;
    int m_finish_microseconds;
    time_t m_last_activity_timestamp;
    bool m_is_finished;
    bool m_empty_connection;

    std::string m_tmp_dir;
    std::string m_final_dir;
    bool m_saved;
    bool m_xml_saved;
    string m_filename_tmp_xml, m_filename_tmp_txt, m_filename_final_xml, m_filename_final_txt;
    bool m_first_save = true;

public:
    Connection (int id_sensor, std::string tmp_dir, std::string final_dir);
    Connection (Packet init_packet, int id_sensor, std::string tmp_dir, std::string final_dir);

    ~Connection();

    // former SQL reader functionality
    string getTimeAndDate();
    string get_hash();
    //void create_files();
    void initialize_filenames();
    void save_files();
    
    void* generate_and_save_wrapper ( void *id_connection );
    void add_packet ( Packet packet, const u_char *packet_dump );
    string get_hex_string ( u_char *data, uint length );
    void save ();
    time_t get_last_activity() { return m_last_activity_timestamp; }
    void finish ( int timestamp, int microseconds );
    void finish();
    void free();
    void free_temp();
    bool finished()
    {
        return m_is_finished;
    }
    
    bool saved()
    {
        return m_saved;
    }
};
    
}

#endif
