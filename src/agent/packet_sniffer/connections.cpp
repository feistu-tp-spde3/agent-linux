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
#include "connections.h"

#include "packet_sniffer.h"

#include "../packetsensor.h"

#include <typeinfo>
#include <iostream>
using namespace std;

namespace packet_sniffer 
{
    Connections::Connections(int id_sensor, string tmp_dir, string final_dir)
    {
        this->m_id_sensor = id_sensor;
        m_tmp_dir = tmp_dir;
        m_final_dir = final_dir;
        
        //create "no-connection" for not assigned packets
        Connection conn(id_sensor, m_tmp_dir, m_final_dir);
        
        Key key;
        
        pair<Key, Connection> item(key, conn);
        
        m_connections.insert(item);
    }
    
    
    Connections::~Connections()
    {
    }
    
    /**
     * find connection with specific key
     * @param key key
     * @return pointer to connection
     */
    Connection *Connections::find(Key key)
    {
        map<Key, Connection>::iterator it;
        it = m_connections.find(key);
        
        //if found
        if (it != m_connections.end())
            return &it->second;
        
        key.reverse();
        it = m_connections.find(key);
        
        if (it != m_connections.end())
            return &it->second;
        
        //if not found
        return NULL;
    }
    
    /**
     * assign packet to its connection and if does not exist, create one
     * @param key key
     * @param packet packet
     */
    void Connections::assign_to_connection(Key *key, Packet *packet, const u_char *packet_dump)
    {
        Connection *conn = find(*key);
        
        if (conn != NULL && !conn->finished())
        {
            conn->add_packet(*packet, packet_dump);
        }
        else
        {
            Connection conn(*packet, m_id_sensor, m_tmp_dir, m_final_dir);
            
            pair<Key, Connection> item(*key, conn);
            
            m_connections.insert(item);
        }
    }
    
    /**
     * close inactive connections, free the memory
     */
    void Connections::cleanup()
    {
        map<Key, Connection>::iterator iter;
        //loop all connections
        for (iter = m_connections.begin(); iter != m_connections.end();)
        {
            if (iter->second.saved())
            {
                //free memory
                m_connections.erase(iter++);
            }
            else
            {
                // CHANGED nemozme vymazat tie packety, lebo este nie su zapisane
                //erase stored packets
                iter->second.free();
                
                time_t act_timestamp = time(NULL);
                //finish connection
                if (act_timestamp - iter->second.get_last_activity() >= INACTIVE_CONNECTION_TIMEOUT)
                    iter->second.finish();
                
                iter++;
            }
        }
    }
    
    /**
     * assign packet to its connection
     * @param packet packet to be stored
     */
    void Connections::add_packet(Packet *packet,  const u_char *packet_dump)
    {    
        int protocol_size = packet->protocols.size();
        
        /*
         *    u_char *dest_eth;
         *    long dest_eth_long;    
         *    
         *    cout << "DEST FROM HEADER: " << packet->dest_mac << endl;
         *    dest_eth = (u_char*)(packet);
         *    cout << "DEST FROM PACKET DUMP: " << dest_eth << endl;  
         */
        
        Key key(packet->source_mac, 
                packet->dest_mac, 
                packet->source_ip, 
                packet->dest_ip, 
                packet->source_port, 
                packet->dest_port);
        
        for (int i = 0; i < protocol_size; i++)
        {
            if (packet->protocols[i].ident == IPPROTO_TCP)
            { 
                //create connection
                if (packet->tcp_flags == TCP_SYN)
                {
                    Connection conn(*packet, m_id_sensor, m_tmp_dir, m_final_dir);
                    
                    pair<Key, Connection> item(key, conn);
                    conn.add_packet(*packet, packet_dump);
                    m_connections.insert(item);
                    break;
                }
                //close connection
                else if (packet->tcp_flags & TCP_FIN)
                {
                    Connection *conn = find(key);
                    
                    if (conn != NULL)
                    {
                        //conn->add_packet(*packet);
                        conn->add_packet(*packet, packet_dump);
                        conn->finish(packet->captured_timestamp, packet->captured_microseconds);
                    }
                    else
                    {
                        //no connection (empty key)
                        Connection *conn = find(Key());
                        if (conn != NULL) 
                        {
                            conn->add_packet(*packet, packet_dump);
                        }
                    }
                }
                //insert into existing connection
                else 
                {
                    Connection *conn = find(key);
                    
                    if (conn != NULL && !conn->finished())
                    {
                        conn->add_packet(*packet, packet_dump);
                    }
                    else
                    {
                        //override key with empty key -  no connection
                        Connection *conn = find(Key());
                        if (conn != NULL)
                            conn->add_packet(*packet, packet_dump);
                    }
                }
                break;
            }
            else if (packet->protocols[i].ident == IPPROTO_UDP)
            {
                //assign_to_connection(&key, packet);
                assign_to_connection(&key, packet, packet_dump);
            }
            else if (packet->protocols[i].ident == IPPROTO_ICMP)
            {
                // assign_to_connection(&key, packet);
                assign_to_connection(&key, packet, packet_dump);
                break;
            }
            else if (packet->protocols[i].ident == IPPROTO_IGMP)
            {
                // assign_to_connection(&key, packet);
                assign_to_connection(&key, packet, packet_dump);
                break;
            }
        }
    }
    
    /**
     * save all packets to db
     */
    void Connections::save(/*Database *db*/) 
    {    
        map<Key, Connection>::iterator iter;
        //loop all connections
        for (iter = m_connections.begin(); iter != m_connections.end(); iter++)
        {
            iter->second.save();
        }
        
        cleanup();
    }
    
}
