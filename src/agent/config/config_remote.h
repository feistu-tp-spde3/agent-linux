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
#ifndef CONFIGCONFIG_REMOTE_H
#define CONFIGCONFIG_REMOTE_H

#include <string>
#include <vector>
#include <map>

#include "../packetsensor.h"

namespace config
{
    
    //connection orientation - source/destination (probably wrong name, 'direction' would be better)
    enum Orientation {SRC, DST};
    
    /**
     * Protocol
     */
    struct Protocol
    {
        int id_protocol;
        std::string name;
        int layer;
        int ident;
    };
    
    /**
     * configuration rule
     */
    struct Config_rule
    {
        uint ip_address;
        long mac_address;
        int port_start;
        int port_end;
        int network;
        int netmask;
        int protocol_ident;
        Orientation orient;
    };
    
    /**
     *          @author Peter Krejci,,, <krejci.peter@gmail.com>
     */
    class Config_remote
    {
    private:
        vector<Config_rule> m_config_rules;
        map<int, Protocol> m_protocol_list;
        int m_iterator;
        int m_id_sensor;
        string m_protocols_filename;
        
        string ip_to_string(long ip);
        string mac_to_string(long mac);

    public:
        Config_remote();
        ~Config_remote();
        
        void init(std::string hash, std::string sensor_name, long sensor_ip, std::string protocols_file);
        void check_configuration();
        void set_protocols(std::string filename);
        string get_expression();
        void reset_iterator() {m_iterator = 0;}
        int get_sensor_id() {return m_id_sensor;}
        Protocol get_protocol(int ident) {return m_protocol_list[ident];}
    };
    
}

#endif
