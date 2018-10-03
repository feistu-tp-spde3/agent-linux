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
#ifndef PACKETSENSOR_H
#define PACKETSENSOR_H

//debug symbol
#define DEBUG
//production symbol
//#define PRODUCTION

/**
 * list of error codes
 */

//database connection error
#define DATABASE_CONNECTION_ERROR 100
//database runtime error
#define DATABASE_RUNTIME_ERROR 101
//write to file error
#define WRITE_FILE_ERROR 102
//read from file error
#define READ_FILE_ERROR 103
//pcap init error
#define PCAP_INIT_ERROR 104
//pcap runtime error
#define PCAP_RUNTIME_ERROR 105

/**
 * configuration files location
 */

//all paths must end with '/'
#define HASH_FILENAME "hash.conf"
#define CONFIG_FILENAME "packetsensor.conf"

#ifdef PRODUCTION
#define CONFIG_PATH "./"
#define DEFAULT_LOGFILE "./packetsensor.log"
#else
#define CONFIG_PATH "./"
#define DEFAULT_LOGFILE "./packetsensor.log"
#endif

/**
 * global marcos
 */
//ethernet headers are always exactly 14 bytes
#define SIZE_ETHERNET 14
//how many packets should be sniffed (-1 until error occures)
#define PACKET_CNT -1
//close connection after this timeout (seconds)
#define INACTIVE_CONNECTION_TIMEOUT 120
//convert integer to string
#define INT_TO_STR(x) #x

/**
 * global objects/variables
 */

//log object
#include "log/log.h"

extern log::Log *logger;
/**
 * type definitions
 */
typedef unsigned int uint;

#endif
