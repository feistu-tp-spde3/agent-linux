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
#include <string>
#include <sstream>
#include <iostream>
#include <stdlib.h>

using namespace std;

#include "config_remote.h"

#include "../packetsensor.h"

#ifdef DEBUG
#include "../debugger/debugger.h"
using namespace debugger;
#endif

#include "../exceptions/eerror.h"


namespace config
{

Config_remote::Config_remote() 
{
    
}
    
// DELETE
// inserting info about sensor instance into the DB
void Config_remote::init(string hash, string sensor_name, long sensor_ip, string protocols_filename)
{
    /*stringstream stm_sensor_ip;
    stm_sensor_ip << sensor_ip;

    try 
    {
        // search for row with particular hash
        q.select("id_sensor, name, ip_address").from("sensor").where("identifier='" + hash + "'");

        Query_result_row row = db->get_row(q);

        //if result is empty, insert new row
        if (row.empty()) 
        {
            q.clear();

            q.insert_into("sensor (`identifier`, `name`, `ip_address`)").values("('" + hash + "', '" + sensor_name + "', '" + stm_sensor_ip.str() + "')");

            db->exec(q);

            id_sensor = db->get_last_insert_id();
        } 
        else 
        {
            istringstream stm_id_sensor(row["id_sensor"]);
            stm_id_sensor >> id_sensor;

            //check if ip address has changed
            if (stm_sensor_ip.str() != row["ip_address"]) {
                *logger << "IP address has changed since last start" << endl;

                q.clear();
                q.update("sensor").set("`ip_address`=" + stm_sensor_ip.str()).where("identifier='" + hash + "'");

                db->exec(q);
            }
        }
    } 
    catch (exceptions::EError& e) 
    {
        throw e;
    }

    *logger << "Sensor hash is: " << hash << endl;
    *logger << "Sensor id is: " << id_sensor << endl;*/
}


Config_remote::~Config_remote()
{

}

/**
 * convert IP address to dotted format
 * @param ip ip address
 * @return IP in dotted format
 */
string Config_remote::ip_to_string(long ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    stringstream stm_ip;
    stm_ip << int(bytes[3]) << "."
           << int(bytes[2]) << "."
           << int(bytes[1]) << "."
           << int(bytes[0]);

    return stm_ip.str();
}

/**
 * convert mac address to double-dotted format
 * @param mac mac address
 * @return mac in double-dotted format
 */
string Config_remote::mac_to_string(long mac)
{
    unsigned char bytes[6];
    bytes[0] = mac & 0xFF;
    bytes[1] = (mac >> 8) & 0xFF;
    bytes[2] = (mac >> 16) & 0xFF;
    bytes[3] = (mac >> 24) & 0xFF;
    bytes[4] = (mac >> 32) & 0xFF;
    bytes[5] = (mac >> 38) & 0xFF;

    stringstream stm_mac;
    stm_mac << hex << int(bytes[5]) << ":"
            << hex << int(bytes[4]) << ":"
            << hex << int(bytes[3]) << ":"
            << hex << int(bytes[2]) << ":"
            << hex << int(bytes[1]) << ":"
            << hex << int(bytes[0]);

    return stm_mac.str();
}

// CHECK set_protocols - nvm ci to funguje
/**
 * protocols initialization
 */
void Config_remote::set_protocols(std::string filename)
{
    ifstream file(filename.c_str());
    
    if (file.is_open())
    {
        m_protocol_list.clear();
        Protocol prot;

        std::string line;
        while (std::getline(file, line))
        {
            std::istringstream iss(line);

            std::string data;
            getline(iss, data, ';'); // get first column into data
            prot.id_protocol = atoi(data.c_str());
            getline(iss, data, ';'); // get second column into data
            prot.name = data;
            getline(iss, data, ';');
            prot.layer = atoi(data.c_str());
            getline(iss, data, ';');
            prot.ident = atoi(data.c_str());

            pair<int, Protocol> item(prot.ident, prot);
            m_protocol_list.insert(item);
        }
    }
    else
    {
        Debugger(LERROR) << "Cannot read protocols!" << endl;
        exit(EXIT_FAILURE);
    }
}

/**
 * return filter expression for pcap
 */
string Config_remote::get_expression()
{
    string expression = "";
    vector<Config_rule>::iterator config_rule;
    bool first = true;

    for (config_rule = m_config_rules.begin(); config_rule < m_config_rules.end(); config_rule++) {
        string direction;
        if (config_rule->orient == SRC)
            direction = " src ";
        else
            direction = " dst ";

        //host
        if (config_rule->ip_address > 0) {
            if (first)
                first = false;
            else
                expression += " and ";
            expression += direction;
            expression += ip_to_string(config_rule->ip_address);
        }

        //mac addresses
        if (config_rule->mac_address > 0) {
            if (first)
                first = false;
            else
                expression += " and ";
            expression += " ether ";
            expression += direction;
            expression += mac_to_string(config_rule->mac_address);
        }


        //port range
        if (config_rule->port_start > 0 && config_rule->port_end > 0) {
            stringstream stm_port_range;
            stm_port_range << config_rule->port_start << "-" << config_rule->port_end;
            if (first)
                first = false;
            else
                expression += " and ";
            expression += direction;
            expression += " portrange ";
            expression += stm_port_range.str();
        }

        //network
        if (config_rule->network > 0) {
            if (first)
                first = false;
            else
                expression += " and ";
            expression += " net ";
            expression += ip_to_string(config_rule->network);
            //netmask - mask cannot be specified without network
            if (config_rule->netmask > 0) {
                expression += " mask ";
                expression += ip_to_string(config_rule->netmask);
            }
        }

        //protocol
        if (config_rule->protocol_ident > 0) {
            if (first)
                first = false;
            else
                expression += " and ";
            expression += " ip proto ";
            stringstream protocol_ident;
            protocol_ident << config_rule->protocol_ident;
            expression += protocol_ident.str();
        }

    }

#ifdef DEBUG
    Debugger() << "Expression: " << expression << endl;
#endif

    return expression;
}

/**
 * check remote configuration
 */
void Config_remote::check_configuration()
{
    // Konfiguracie v povodnej DB neboli nastavene, preto je toto zrejme cele zbytocne, nechal som to tu
    // len pre pripad potreby v buducnosti.
    /*Database_query q;

    try {
        //get all config rules

        ostringstream stm_id_sensor;
        stm_id_sensor << id_sensor;

        q.select("config.*, protocol.ident").from("config").left_join("protocol").using_col("id_protocol");
        q.where("id_sensor='" + stm_id_sensor.str() + "' OR id_sensor IS NULL");

        Query_result_table rules = db->get_all(q);

        //clear all rules
        config_rules.clear();

        int num_rows = rules.num_rows();
        for (int row = 0; row < num_rows; row++) {
            //string to int conversion...
            istringstream stm_ip_address(rules[row]["ip_address"]);
            istringstream stm_mac_address(rules[row]["mac_address"]);
            istringstream stm_port_start(rules[row]["port_start"]);
            istringstream stm_port_end(rules[row]["port_end"]);
            istringstream stm_network(rules[row]["network"]);
            istringstream stm_netmask(rules[row]["netmask"]);
            istringstream stm_ident(rules[row]["ident"]);

            Config_rule rule;
            int ident;

            stm_ip_address  >> rule.ip_address;
            stm_mac_address >> rule.mac_address;
            stm_port_start  >> rule.port_start;
            stm_port_end    >> rule.port_end;
            stm_network     >> rule.network;
            stm_netmask     >> rule.netmask;
            stm_ident       >> ident;

            rule.protocol_ident = ident;
            rule.orient   = rules[row]["orient"] == "SRC" ? SRC : DST;

            config_rules.push_back(rule);
        }
    } catch (exceptions::EError& e) {
        throw e;
    }*/
}

}

