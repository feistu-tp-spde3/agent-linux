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
#ifndef PACKET_SNIFFERCONNECTIONS_H
#define PACKET_SNIFFERCONNECTIONS_H

#include <arpa/inet.h> //IP protocol constants

#include "connection.h"

namespace packet_sniffer 
{
    /**
     *          @author Peter Krejci,,, <krejci.peter@gmail.com>
     */
    class Connections
    {
        //inner class representing connection key
        class Key {
        private:
            long m_mac_1;
            long m_mac_2;
            uint m_ip_1;
            uint m_ip_2;
            int m_port_1;
            int m_port_2;
        public:
            Key() { m_mac_1 = m_mac_2 = m_ip_1 = m_ip_2 = m_port_1 = m_port_2 = 0; }
            Key(long mac_1, long mac_2, uint ip_1, uint ip_2, int port_1, int port_2) 
            {
                this->m_mac_1 = mac_1;
                this->m_mac_2 = mac_2;
                this->m_ip_1 = ip_1;
                this->m_ip_2 = ip_2;
                this->m_port_1 = port_1;
                this->m_port_2 = port_2;
            }
            /**
             * reverse values (src<->dst)
             */ 
            void reverse() 
            {
                long l_tmp = m_mac_1;
                m_mac_1 = m_mac_2;
                m_mac_2 = l_tmp;
                
                int i_tmp = m_ip_1;
                m_ip_1 = m_ip_2;
                m_ip_2 = i_tmp;
                
                i_tmp = m_port_1;
                m_port_1 = m_port_2;
                m_port_2 = i_tmp;
            }
            
            // comparison operator
            bool operator<(const Key &key) const
            { //compare like one 256bit number split into small parts
                if (!(m_mac_1 ^ key.m_mac_1))
                {
                    if (!(m_mac_2 ^ key.m_mac_2))
                    {
                        if (!(m_ip_1 ^ key.m_ip_1))
                        {
                            if (!(m_ip_2 ^ key.m_ip_2))
                            {
                                if (!(m_port_1 ^ key.m_port_1))
                                {
                                    return m_port_2 < key.m_port_2;
                                } 
                                else 
                                {
                                    return m_port_1 < key.m_port_1;
                                }
                            } 
                            else 
                            {
                                return m_ip_2 < key.m_ip_2;
                            }
                        } 
                        else 
                        {
                            return m_ip_1 < key.m_ip_1;
                        }
                    } 
                    else 
                    {
                        return m_mac_2 < key.m_mac_2;
                    }
                } 
                else 
                {
                    return m_mac_1 < key.m_mac_1;
                }
            }
        };
        
    private:
        int m_id_sensor;
        map<Key, Connection> m_connections;
        
        string m_tmp_dir;
        string m_final_dir;
        
        Connection *find(Key key);
        void assign_to_connection(Key *key, Packet *packet, const u_char *packet_dump);
        void cleanup();
        
    public:
        Connections(int m_id_sensor, string tmp_dir, string final_dir);
        
        ~Connections();
        
        void set_sensor_id(int id_sensor) {this->m_id_sensor = id_sensor;}
        void add_packet(Packet *packet, const u_char *packet_dump);
        void save(/*Database *db*/);
    };
    
}

#endif
