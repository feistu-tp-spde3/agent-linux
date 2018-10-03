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
#include "connection.h"

#include <typeinfo>

#include <iostream>
#include <string.h>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "sha256.h"
#include <string>
#include <sstream>
#include <fstream>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <fcntl.h>

using namespace std;

#include "../packetsensor.h"
#include "../debugger/debugger.h"

using namespace debugger;

// CHECK DELETE pozri či treba tieto define-y
#define IP_PACKET_START_BYTE 15
#define IP_ADDR_START_BYTE 26
#define IP_PROTOCOL_BYTE 10
#define UDP_PROTOCOL 17
#define TCP_PROTOCOL 6

namespace packet_sniffer
{

/*-------------------------------------------------------------------*/
/* SQL Reader part */
template <typename T>
string to_string(T value)
{
    //create an output string stream
    ostringstream os ;

    //throw the value into the string stream
    os << value ;

    //convert the string stream into a string and return
    return os.str() ;
}

string Connection::getTimeAndDate()
{
    time_t raw_time;
    struct tm* time_info;
    int day, month, year, hour, minute, seconds;
    string dateTime;

    time(&raw_time);
    time_info = localtime(&raw_time);
    year = time_info->tm_year + 1900;
    month = time_info->tm_mon + 1;
    day = time_info->tm_mday;
    hour = time_info->tm_hour;
    minute = time_info->tm_min;
    seconds = time_info->tm_sec;

    dateTime.append(to_string(year));

    if (month < 10) {
        dateTime.append("0");
        dateTime.append(to_string(month));
    } else {
        dateTime.append(to_string(month));
    }

    if (day < 10) {
        dateTime.append("0");
        dateTime.append(to_string(day));
    } else {
        dateTime.append(to_string(day));
    }

    dateTime.append("_");

    if (hour < 10) {
        dateTime.append("0");
        dateTime.append(to_string(hour));
    } else {
        dateTime.append(to_string(hour));
    }

    if (minute < 10) {
        dateTime.append("0");
        dateTime.append(to_string(minute));
    } else {
        dateTime.append(to_string(minute));
    }

    if (seconds < 10) {
        dateTime.append("0");
        dateTime.append(to_string(seconds));
    } else {
        dateTime.append(to_string(seconds));
    }

    return dateTime;
}

// creates hash that serves as identifier for the connection
string Connection::get_hash()
{
    stringstream stream;
    unsigned int protocol;
    unsigned int port;
    const u_char* dump;
    unsigned char ihl, port_data_offset;

    stream << m_ip_source_machine;
    stream << m_ip_dest_machine;
    dump = m_first_dump.data;
    protocol = dump[IP_PACKET_START_BYTE - 1 + IP_PROTOCOL_BYTE - 1] & 0xFF;


    if ((protocol == UDP_PROTOCOL) || (protocol == TCP_PROTOCOL))
    {
        ihl = dump[IP_PACKET_START_BYTE - 1] & 0x0F; //get IHL internet header l$
        port_data_offset = ihl * 4;
        port_data_offset += IP_PACKET_START_BYTE - 1;
        stream << protocol;

        port = (unsigned int)(dump[port_data_offset] & 0xFF) << 8;
        port += (dump[port_data_offset + 1] & 0xFF);
        stream << port;

        port = (unsigned int)(dump[port_data_offset + 2] & 0xFF) << 8;
        port += (dump[port_data_offset + 3] & 0xFF);
        stream << port;
    }

    return sha256(stream.str());
}

void Connection::initialize_filenames()
{
    string hash = get_hash().substr(0, 10);
    string name = hash + "-" + getTimeAndDate();

    vector<string> filenames(4);

    m_filename_tmp_xml = m_tmp_dir + name + ".xml";
    m_filename_tmp_txt = m_tmp_dir + name + ".txt";
    m_filename_final_xml = m_final_dir + name + ".xml";
    m_filename_final_txt = m_final_dir + name + ".txt";
}

void Connection::save_files()
{
    int count;

    count = m_temp_dumps.size();
    if (count <= 0)
    {
        return;
    }

    string name;
    unsigned char protocol, ihl, ip_version, port_data_offset;

    unsigned int port;
    long unsigned int addr;
    int dump_length;
    stringstream id_connection_s;
    const u_char* dump;

    // if first run -> initialize filenames and create the XML file
    if (m_first_save)
    {
        m_first_save = false;
        initialize_filenames();

        // XML file
        FILE *file_packets_XML;
        file_packets_XML = fopen(m_filename_tmp_xml.c_str(), "w");

        fprintf(file_packets_XML, "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>\n");
        fprintf(file_packets_XML, "<item>\n");
        fprintf(file_packets_XML, "<SessID>%s</SessID>\n", name.c_str());

        dump = m_first_dump.data;
        protocol = dump[IP_PACKET_START_BYTE - 1 + IP_PROTOCOL_BYTE - 1] & 0xFF;
        if (true)
        {
            fprintf(file_packets_XML, "<IP_Protocol>IPv4</IP_Protocol>\n");
            addr = m_ip_source_machine;
            fprintf(file_packets_XML, "<SrcAddr>%u.%u.%u.%u</SrcAddr>\n", addr >> 24, (addr  >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
            addr = m_ip_dest_machine;
            fprintf(file_packets_XML, "<DstAddr>%u.%u.%u.%u</DstAddr>\n",  addr >> 24, (addr  >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF);
        }

        //fprintf(filePacketsXML, "%i", protocol);

        if (protocol == UDP_PROTOCOL)
        {
            ihl = dump[IP_PACKET_START_BYTE - 1] & 0x0F; //get IHL internet header length
            port_data_offset = ihl * 4;
            port_data_offset += IP_PACKET_START_BYTE - 1;

            fprintf(file_packets_XML, "<CoreProtocol>UDP</CoreProtocol>\n");

            port = (unsigned int)(dump[port_data_offset] & 0xFF) << 8;
            port += (dump[port_data_offset + 1] & 0xFF);
            fprintf(file_packets_XML, "<SrcPort>%u</SrcPort>\n", port);

            port = (unsigned int)(dump[port_data_offset + 2] & 0xFF) << 8;
            port += (dump[port_data_offset + 3] & 0xFF);
            fprintf(file_packets_XML, "<DstPort>%u</DstPort>\n", port);
        }

        if (protocol == TCP_PROTOCOL)
        {
            ihl = dump[IP_PACKET_START_BYTE - 1] & 0x0F;
            port_data_offset = ihl * 4;
            port_data_offset += IP_PACKET_START_BYTE - 1;

            fprintf(file_packets_XML, "<CoreProtocol>TCP</CoreProtocol>\n");

            port = (unsigned int)(dump[port_data_offset] & 0xFF) << 8;
            port += (dump[port_data_offset + 1] & 0xFF);
            fprintf(file_packets_XML, "<SrcPort>%u</SrcPort>\n", port);

            port = (unsigned int)(dump[port_data_offset + 2] & 0xFF) << 8;
            port += (dump[port_data_offset + 3] & 0xFF);
            fprintf(file_packets_XML, "<DstPort>%u</DstPort>\n", port);
        }

        fprintf(file_packets_XML, "<NoPackets>%i</NoPackets>\n", count);
        fprintf(file_packets_XML, "</item>");
        fclose(file_packets_XML);
    }

    // saving packet dump
    FILE *file_packets_TXT;
    if (m_first_save)
    {
        file_packets_TXT = fopen(m_filename_tmp_txt.c_str(), "w");
    }
    else
    {
        file_packets_TXT = fopen(m_filename_tmp_txt.c_str(), "a");
    }

    // saving name
    fprintf(file_packets_TXT, "\r\n%s\r\n", name.c_str());

    // saving raw packets
    for (int p = 0; p < m_temp_packets.size(); p++)
    {
        dump_length = m_temp_dumps[p].length;
        dump = m_temp_dumps[p].data;

        fprintf(file_packets_TXT, "\r\n%i\r\n", m_temp_packets[p].captured_timestamp);

        for (int byte = 0; byte < dump_length; byte++)
        {
            if ((byte % 16) == 0)
            {
                fprintf(file_packets_TXT, "\r\n");
            }

            fprintf(file_packets_TXT, "%02X ", (unsigned char)dump[byte]);
        }
        fprintf(file_packets_TXT, "\r\nEnd of packet\r\n");
    }
    fprintf(file_packets_TXT, "\r\nEnd of Packets File\r\n");

    fclose(file_packets_TXT);

    free_temp();

    Debugger(LINFO) << "Moving files to final --------------------------------" << endl;
    Debugger(LINFO) << m_filename_tmp_txt.c_str() << " -> " << m_filename_final_txt.c_str() << endl;
    Debugger(LINFO) << m_filename_tmp_xml.c_str() << " -> " << m_filename_final_xml.c_str() << endl;
    cout << "-------------------------------------------------------------" << endl;

    rename(m_filename_tmp_txt.c_str(), m_filename_final_txt.c_str());  //presun suboru txt do final priecinka
    rename(m_filename_tmp_xml.c_str(), m_filename_final_xml.c_str());  //presun xml suboru do final priecinka
}

/* SQL Reader part */
/*-------------------------------------------------------------------*/

/* Function for starting the file save.
*/
void* Connection::generate_and_save_wrapper(void* id_connection)
{
    int* id = (int*)id_connection;

    char* config_path;
    
    // NOTE pre zlepsenie behu je mozne pridat thread, ktory bude mat za ulohu zapis suborov, aby to nebezalo v main threade
    save_files();
    cout << "Files successfully created." << endl;

    return NULL;
}


Connection::Connection(int id_sensor, string tmp_dir, string final_dir):
    m_empty_connection(true),
    m_id_connection(NOT_DEFINED),
    m_is_finished(false),
    m_saved(false)
{
    this->m_id_sensor = id_sensor;
    m_tmp_dir = tmp_dir;
    m_final_dir = final_dir;
}

Connection::Connection(Packet init_packet, int id_sensor, string tmp_dir, string final_dir):
    m_empty_connection(false),
    m_id_connection(NOT_DEFINED),
    m_is_finished(false),
    m_saved(false)
{
    m_mac_source_machine = init_packet.source_mac;
    m_mac_dest_machine = init_packet.dest_mac;

    m_ip_source_machine = init_packet.source_ip;
    m_ip_dest_machine = init_packet.dest_ip;

    m_port_source_machine = init_packet.source_port;
    m_port_dest_machine = init_packet.dest_port;

    m_start_timestamp = init_packet.captured_timestamp;
    m_start_microseconds = init_packet.captured_microseconds;

    m_last_activity_timestamp = time(NULL);

    m_id_sensor = id_sensor;
    
    m_tmp_dir = tmp_dir;
    m_final_dir = final_dir;
}


Connection::~Connection()
{
}

/**
 * add packet to this connection
 * @param packet captured packet
 */
void Connection::add_packet(Packet packet, const u_char* packet_dump)
{
    m_last_activity_timestamp = time(NULL);
    m_packets.push_back(packet);

    Dump dump;

    dump.data = new u_char[packet.length]; //allocating memory for packet dump
    memcpy(dump.data, packet_dump, (size_t)packet.length); // copying packet dump
    dump.length = packet.length;
    m_dumps.push_back(dump);

    // initializing the first dump, that is later used in get_hash
    if (m_first_dump.length == 0)
    {
        m_first_dump = dump;
    }
}
/**
 * close connection
 * @param integer finish timestamp
 * @param integer finish microseconds
 */
void Connection::finish(int timestamp, int microseconds)
{
    m_finish_timestamp = timestamp;
    m_finish_microseconds = microseconds;
    m_is_finished = true;
}

/**
 * overriden method - empty timestamps, finished after inactivity
 */
void Connection::finish()
{
    m_finish_timestamp = 0;
    m_finish_microseconds = 0;
    m_is_finished = true;
}

string Connection::get_hex_string(u_char* data, uint length)
{
    stringstream ss;

    ss << hex;
    for (int i = 0; i < length; i++)
        ss << setfill('0') << setw(2) << (int)data[i];

    return ss.str();
}



/**
 * save connection
 */
void Connection::save()
{
    vector<Packet>::const_iterator captured_packet;
    vector<Dump>::iterator actual_dump;

    // save connection (session) (if this is a new connection)
    if (m_id_connection == NOT_DEFINED)
    {
        if (m_empty_connection)
        {
            m_id_connection = EMPTY_CONNECTION;
        }
    }

    //NOTE/TODO: some performance improvement could be done
    //if finished connection created in one cycle are stored
    //in one step (above)

    // saving the actual packet body (dump)
    if (m_packets.size() > 0)
    {
        // CHECK nvm ci sa robi plytka alebo hlboka kopia
        m_temp_dumps = m_dumps;
        m_temp_packets = m_packets;
        free();

        save_files();
    }

    //if connection is finished, update database
    if (m_is_finished)
    {
        //        Database_query q;
        stringstream set, where;
        pthread_t* thread_id;
        int* id_connection;


        /*set << "`finish_timestamp`=" << m_finish_timestamp << ", `finish_microseconds`=" << m_finish_microseconds;
        where << "`id_connection`=" << id_connection;
//        q.update("connection").set(set.str()).where(where.str());

//        db->exec(q);

        thread_id = (pthread_t*)malloc(sizeof(pthread_t));
        id_connection = (int*)malloc(sizeof(int));

        *id_connection = this->m_id_connection;*/
        save_files();
        m_saved = true;

        //        pthread_create(thread_id , NULL, &Connection::generate_and_save_wrapper, (void*)id_connection);
    }
}

/**
 * drop all stored packets
 */
void Connection::free()
{
    // TODO pridat cistenie pamate
    m_packets.clear();
    vector<Packet>().swap(m_packets);
    for (int i = 0; i < m_dumps.size(); i++)
    {
        delete m_dumps[i].data;
    }
    m_dumps.clear();
    vector<Dump>().swap(m_dumps);
}

void Connection::free_temp()
{
    // TODO pridat cistenie pamate
    m_temp_packets.clear();
    vector<Packet>().swap(m_temp_packets);
    for (int i = 0; i < m_temp_dumps.size(); i++)
    {
        if (m_temp_dumps[i].data[0] == '\n')
            delete[] m_temp_dumps[i].data;
    }
    m_temp_dumps.clear();
    vector<Dump>().swap(m_temp_dumps);
}

}
