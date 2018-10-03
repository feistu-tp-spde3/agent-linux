// ConfigFile.cpp

//for license terms read configFile.h

#include "configFile.h"

#include "../exceptions/eread_file_error.h"

using std::string;

ConfigFile::ConfigFile( string filename, string delimiter,
                        string comment, string sentry )
: m_delimiter(delimiter), m_comment(comment), m_sentry(sentry)
{
    // Construct a ConfigFile, getting keys and values from given file
    std::ifstream in( filename.c_str() );
    
    if( !in ) throw exceptions::ERead_file_error();
    
    in >> (*this);
}


ConfigFile::ConfigFile()
: m_delimiter( string(1,'=') ), m_comment( string(1,'#') )
{
    // Construct a ConfigFile without a file; empty
}


void ConfigFile::remove( const string& key )
{
    // Remove key and its value
    m_contents.erase( m_contents.find( key ) );
    return;
}


bool ConfigFile::keyExists( const string& key ) const
{
    // Indicate whether key is found
    m_mapci p = m_contents.find( key );
    return ( p != m_contents.end() );
}


/* static */
void ConfigFile::trim( string& s )
{
    // Remove leading and trailing whitespace
    static const char whitespace[] = " \n\t\v\r\f";
    s.erase( 0, s.find_first_not_of(whitespace) );
    s.erase( s.find_last_not_of(whitespace) + 1U );
}


std::ostream& operator<<( std::ostream& os, const ConfigFile& cf )
{
    // Save a ConfigFile to os
    for( ConfigFile::m_mapci p = cf.m_contents.begin();
        p != cf.m_contents.end();
    ++p )
        {
            os << p->first << " " << cf.m_delimiter << " ";
            os << p->second << std::endl;
        }
        return os;
}


std::istream& operator>>( std::istream& is, ConfigFile& cf )
{
    // Load a ConfigFile from is
    // Read in keys and values, keeping internal whitespace
    typedef string::size_type pos;
    const string& delim  = cf.m_delimiter;  // separator
    const string& comm   = cf.m_comment;    // comment
    const string& sentry = cf.m_sentry;     // end of file sentry
    const pos skip = delim.length();        // length of separator
    
    string nextline = "";  // might need to read ahead to see where value ends
    
    while( is || nextline.length() > 0 )
    {
        // Read an entire line at a time
        string line;
        if( nextline.length() > 0 )
        {
            line = nextline;  // we read ahead; use it now
            nextline = "";
        }
        else
        {
            std::getline( is, line );
        }
        
        // Ignore comments
        line = line.substr( 0, line.find(comm) );
        
        // Check for end of file sentry
        if( sentry != "" && line.find(sentry) != string::npos ) return is;
        
        // Parse the line if it contains a delimiter
        pos delimPos = line.find( delim );
        if( delimPos < string::npos )
        {
            // Extract the key
            string key = line.substr( 0, delimPos );
            line.replace( 0, delimPos+skip, "" );
            
            // See if value continues on the next line
            // Stop at blank line, next line with a key, end of stream,
            // or end of file sentry
            bool terminate = false;
            while( !terminate && is )
            {
                std::getline( is, nextline );
                terminate = true;
                
                string nlcopy = nextline;
                ConfigFile::trim(nlcopy);
                if( nlcopy == "" ) continue;
                
                nextline = nextline.substr( 0, nextline.find(comm) );
                if( nextline.find(delim) != string::npos )
                    continue;
                if( sentry != "" && nextline.find(sentry) != string::npos )
                    continue;
                
                nlcopy = nextline;
                ConfigFile::trim(nlcopy);
                if( nlcopy != "" ) line += "\n";
                line += nextline;
                terminate = false;
            }
            
            // Store key and value
            ConfigFile::trim(key);
            ConfigFile::trim(line);
            cf.m_contents[key] = line;  // overwrites if key is repeated
        }
    }
    
    return is;
}
