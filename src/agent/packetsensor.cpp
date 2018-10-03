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
#include <cstdlib>

using namespace std;

#include "packetsensor.h"

#include "log/log.h"

#include "exceptions/eerror.h"

#include "config/config_hash.h"
#include "config/config_local.h"

using namespace config;

#include "packet_sniffer/packet_sniffer.h"

using namespace packet_sniffer;

// global variables and objects
log::Log *logger;

int verbosity;		// log level

/**
 * Main function
 * 
 * @param argc 
 * @param argv[] 
 * @return return code
 */
int main(int argc, char *argv[])
{
    logger = NULL;
    verbosity = 1;
    
    //whole program execution is in try block
    //so we can catch all exceptions and show appropiate message
    
    try 
    {   
        // loads config
        Config_hash config_hash;
        
        config_hash.init();
        
        Config_local config_local;
        
        config_local.read_configuration();
        
        logger = new log::Log(config_local.get_logfile_path());
        
        *logger << "Configuration file read, packetSensor starting..." << endl;
        
        //--------create and run packet sniffer----------
        Packet_sniffer packet_sniffer(config_local.get_output_interval());
        
        packet_sniffer.run(config_hash, config_local);
        cout << "STOP" << endl;
    } 
    catch (exceptions::EError &e) 
    {    
        //log it
        if (logger == NULL)
            logger = new log::Log(DEFAULT_LOGFILE);
        
        *logger <<  e.what() << endl;
        *logger << "Error Code: " << e.get_error_code() << endl;
        
        *logger << "View logfile for more information" << endl;
        
        
        *logger << "Exiting..." << endl;
        
        if (logger != NULL)
            delete logger;
        
        return e.get_error_code();
    }
    if (logger != NULL)
        delete logger;
    
    return EXIT_SUCCESS;
}
