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
#ifndef CONFIGCONFIG_LOCAL_H
#define CONFIGCONFIG_LOCAL_H

#include <string>

using namespace std;

namespace config
{
    
    enum Server_type {T_MYSQL};
    /**
     *          @author Peter Krejci,,, <krejci.peter@gmail.com>
     */
    class Config_local
    {
    private:
        string m_sensor_name;
        bool m_compression; // DELETE ?
        bool m_encryption; // DELETE ?
        int m_output_interval;
        string m_logfile_path;
        string m_collector_sender_path;
        string m_collector_sender_conf;
        
        string m_tmp_dir;
        string m_final_dir;
        string m_protocol_filename;
        
    public:
        Config_local();
        
        ~Config_local();
        
        void read_configuration();
        
        string get_sensor_name() {return m_sensor_name;}
        bool compress() {return m_compression;}
        bool encrypt() {return m_encryption;}
        int get_output_interval() {return m_output_interval;}
        string get_logfile_path() {return m_logfile_path;}
        string get_collector_sender_path() {return m_collector_sender_path;}
        string get_collector_sender_conf() {return m_collector_sender_conf;}
        
        string get_tmp_dir() {return m_tmp_dir;}
        string get_final_dir() {return m_final_dir;}
        string get_protocol_filename() {return m_protocol_filename;}
    };
    
}

#endif
