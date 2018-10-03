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
#include <ctime>
#include <iostream>
#include <cstring>

#include "log.h"

#include "../exceptions/ewrite_file_error.h"

namespace log
{

/**
 * constructor
 * @param filename log file name
 */
Log::Log(string filename)
{
    m_logfile.open(filename.c_str(), ios_base::app);

    if (!m_logfile.is_open())
        throw exceptions::EWrite_file_error();
}


Log::~Log()
{
    if (m_logfile.is_open())
        m_logfile.close();
}

/**
 * stores log mesage into stream
 * @param t string
 * @return this
 */
Log& Log::operator<<(const char* t)
{
    m_message << t;
    return *this;
}

/**
 * stores log mesage into stream
 * @param s string
 * @return this
 */
Log& Log::operator<<(string s)
{
    m_message << s;
    return *this;
}

/**
 * stores log mesage into stream
 * @param val integer value
 * @return this
 */
Log& Log::operator<<(int val)
{
    m_message << val;
    return *this;
}

/**
 * stores stream into log file
 * @param (* pf)(ostream &) manipulator (endl expected)
 * @return this
 */
Log& Log::operator<<(ostream & (*pf)(ostream&))
{

    m_message << (*pf);

    if (!m_logfile.is_open())
        throw exceptions::EWrite_file_error();

    //get current date and time
    time_t rawtime;

    time(&rawtime);

    char* act_time = ctime(&rawtime);

    //remove last '\n' from act_time - we don't need it!
    act_time[strlen(act_time) - 1] = '\0';

    m_logfile << act_time << ": " << m_message.str();

    //print on standard error output
    cerr << m_message.str();

    //clear buffer
    m_message.str("");

    return *this;
}
}
