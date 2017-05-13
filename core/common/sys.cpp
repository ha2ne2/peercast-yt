// ------------------------------------------------
// File : sys.cpp
// Date: 4-apr-2002
// Author: giles
// Desc:
//      Sys is a base class for all things systemy, like starting threads, creating sockets etc..
//      Lock is a very basic cross platform CriticalSection class
//      SJIS-UTF8 conversion by ????
//
// (c) 2002 peercast.org
// ------------------------------------------------
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// ------------------------------------------------

#include "common.h"
#include "sys.h"
#include "gnutella.h"
#include <stdlib.h>
#include <time.h>

// -----------------------------------
const char *LogBuffer::logTypes[]=
{
    "",
    "DBUG",
    "EROR",
    "GNET",
    "CHAN",
};

// ------------------------------------------
Sys::Sys()
{
    idleSleepTime = 10;
    logBuf = new LogBuffer(1000, 100);
    numThreads=0;
}

// ------------------------------------------
Sys::~Sys()
{
    delete logBuf;
}

// ------------------------------------------
void Sys::sleepIdle()
{
    sleep(idleSleepTime);
}

// -----------------------------------
char *trimstr(char *s1)
{
    while (*s1)
    {
        if ((*s1 == ' ') || (*s1 == '\t'))
            s1++;
        else
            break;
    }

    char *s = s1;

    s1 = s1+strlen(s1);

    while (*--s1)
        if ((*s1 != ' ') && (*s1 != '\t'))
            break;

    s1[1] = 0;

    return s;
}

// -----------------------------------
char *stristr(const char *s1, const char *s2)
{
    while (*s1)
    {
        if (TOUPPER(*s1) == TOUPPER(*s2))
        {
            const char *c1 = s1;
            const char *c2 = s2;

            while (*c1 && *c2)
            {
                if (TOUPPER(*c1) != TOUPPER(*c2))
                    break;
                c1++;
                c2++;
            }
            if (*c2==0)
                return (char *)s1;
        }

        s1++;
    }
    return NULL;
}

// -----------------------------------
void LogBuffer::write(const char *str, TYPE t)
{
    lock.on();

    unsigned int len = strlen(str);
    int cnt=0;
    while (len)
    {
        unsigned int rlen = len;
        if (rlen > (lineLen-1))
            rlen = lineLen-1;

        int i = currLine % maxLines;
        int bp = i*lineLen;
        strncpy(&buf[bp], str, rlen);
        buf[bp+rlen] = 0;
        if (cnt==0)
        {
            times[i] = sys->getTime();
            types[i] = t;
        }else
        {
            times[i] = 0;
            types[i] = T_NONE;
        }
        currLine++;

        str += rlen;
        len -= rlen;
        cnt++;
    }

    lock.off();
}

// -----------------------------------
const char *getCGIarg(const char *str, const char *arg)
{
    if (!str)
        return NULL;

    const char *s = strstr(str, arg);

    if (!s)
        return NULL;

    s += strlen(arg);

    return s;
}

// -----------------------------------
bool cmpCGIarg(const char *str, const char *arg, const char *value)
{
    if ((!str) || (!strlen(value)))
        return false;

    if (strnicmp(str, arg, strlen(arg)) == 0)
    {
        str += strlen(arg);

        return strncmp(str, value, strlen(value))==0;
    }else
        return false;
}

// -----------------------------------
bool hasCGIarg(const char *str, const char *arg)
{
    if (!str)
        return false;

    const char *s = strstr(str, arg);

    if (!s)
        return false;

    return true;
}

// ---------------------------
void LogBuffer::escapeHTML(char* dest, char* src)
{
    while (*src)
    {
        switch (*src)
        {
        case '&':
            strcpy(dest, "&amp;");
            dest += 5;
            break;
        case '<':
            strcpy(dest, "&lt;");
            dest += 4;
            break;
        case '>':
            strcpy(dest, "&gt;");
            dest += 4;
            break;
        default:
            *dest = *src;
            dest++;
        }
        src++;
    }
    *dest = '\0';
}

// ---------------------------
void LogBuffer::dumpHTML(Stream &out)
{
    lock.on();

    unsigned int nl = currLine;
    unsigned int sp = 0;
    if (nl > maxLines)
    {
        nl = maxLines-1;
        sp = (currLine+1)%maxLines;
    }

    String tim;
    const size_t BUFSIZE = (lineLen - 1) * 5 + 1;
    char* escaped = new char [BUFSIZE];
    if (nl)
    {
        for (unsigned int i=0; i<nl; i++)
        {
            unsigned int bp = sp*lineLen;

            if (types[sp])
            {
                tim.setFromTime(times[sp]);

                out.writeString(tim.cstr());
                out.writeString(" <b>[");
                out.writeString(getTypeStr(types[sp]));
                out.writeString("]</b> ");
            }

            escapeHTML(escaped, &buf[bp]);
            out.writeString(escaped);
            out.writeString("<br>");

            sp++;
            sp %= maxLines;
        }
    }
    delete[] escaped;

    lock.off();
}

// ---------------------------
void    ThreadInfo::shutdown()
{
    active = false;
    //sys->waitThread(this);
}
