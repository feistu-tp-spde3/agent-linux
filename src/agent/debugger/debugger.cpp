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

#include "debugger.h"

namespace debugger {

Debugger::Debugger(LogType lt)
{
    if (lt == LDEBUG)
        cout << "[DEBUG] ";
    else if (lt == LINFO)
        cout << "[INFO] ";
    else if (lt == LERROR)
        cout << "[ERROR] ";
}


Debugger::~Debugger()
{
}

/**
     * prints debug message on standard output
     * @param t string
     * @return this
     */
Debugger &Debugger::operator<<(const char *t)
{
    cout << t;
    return *this;
}

/**
     * prints debug message on standard output
     * @param s string
     * @return this
     */
Debugger &Debugger::operator<<(std::string s)
{
    cout << s;
    return *this;
}

/**
     * prints debug message on standard output
     * @param (* pf)(ostream &) manipulator
     * @return this
     */
Debugger &Debugger::operator<<(ostream& (*pf)(ostream&))
{
    cout << (*pf);
    return *this;
}

/**
     * prints debug message on standard output
     * @param (* pf)(ostream &) manipulator
     * @return this
     */
Debugger &Debugger::operator<<(int val)
{
    cout << val;
    return *this;
}
}
