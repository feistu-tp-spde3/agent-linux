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
#include <stdlib.h>
#include "config_local.h"

#include "../packetsensor.h"

#ifdef DEBUG
#include "../debugger/debugger.h"
using namespace debugger;
#endif

#include "../exceptions/eread_file_error.h"

using namespace exceptions;

#include "configFile.h" //3rd part config file parser

namespace config
{

Config_local::Config_local()
{
}


Config_local::~Config_local()
{
}

/**
 * Read configuration from file
 */
void Config_local::read_configuration()
{

    try {
        ConfigFile config(CONFIG_PATH CONFIG_FILENAME);

        config.readInto(m_sensor_name, "sensor_name");

        //server type is stored as enumeration - we have to transform
        string serv_type;
        
        //compression and encryption are boolean values
        string comp;
        string enc;
        config.readInto(comp, "compression");
        config.readInto(enc, "encryption");

        m_compression = comp == "true" ? true : false;
        m_encryption  = enc == "true" ? true : false;

        m_output_interval = -2;
        config.readInto(m_output_interval, "connection_interval");
        if (m_output_interval == -2)
        {
            Debugger(LERROR) << "[ERROR] Connection interval not set !";
            exit(EXIT_FAILURE);
        }
        config.readInto(m_logfile_path, "logfile");
        if (m_logfile_path.empty())
        {
            Debugger(LERROR) << "[ERROR] Log file not set !";
            exit(EXIT_FAILURE);
        }
        config.readInto(m_collector_sender_path, "collectorsender");
        if (m_collector_sender_path.empty())
        {
            Debugger(LERROR) << "[ERROR] CollectorSender dir not set !";
            exit(EXIT_FAILURE);
        }
        config.readInto(m_collector_sender_conf, "collectorsender_conf");
        if (m_collector_sender_conf.empty())
        {
            Debugger(LERROR) << "[ERROR] CollectorSender conf file not set !";
            exit(EXIT_FAILURE);
        }
        // from SQLReader
        config.readInto(m_tmp_dir, "temporary_dir");
        if (m_tmp_dir.empty())
        {
            Debugger(LERROR) << "[ERROR] Temporary dump dir not set !";
            exit(EXIT_FAILURE);
        }
        config.readInto(m_final_dir, "final_dir");
        if (m_final_dir.empty())
        {
            Debugger(LERROR) << "[ERROR] Final dump dir not set !";
            exit(EXIT_FAILURE);
        }
        config.readInto(m_protocol_filename, "protocol_filename");
        if (m_protocol_filename.empty())
        {
            Debugger(LERROR) << "[ERROR] Protocols filename not set !";
            exit(EXIT_FAILURE);
        }


#ifdef DEBUG
        Debugger(LINFO) << "sensor_name = " << m_sensor_name << endl;
        Debugger(LINFO) << "compression = " << comp << endl;
        Debugger(LINFO) << "encryption = " << enc << endl;
        Debugger(LINFO) << "output_interval = " << m_output_interval << endl;
        Debugger(LINFO) << "logfile = " << m_logfile_path << endl;
#endif

    } catch (...) {

        throw ERead_file_error();
    }


}

}
