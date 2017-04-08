// ------------------------------------------------
// File : incoming.h
// Author: giles
// Desc:
//
// (c) peercast.org
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

#ifndef _INCOMING_H
#define _INCOMING_H

#include "html.h"
#include "http.h"
#include "channel.h"
#include "servent.h"

// IncomingController handles incoming HTTP-like connections.
class IncomingController
{
public:
    IncomingController(Servent* aServ, ClientSocket*& aSock, HTTP& anHTTP, Cookie& aCookie)
        : servent(aServ)
        , http(anHTTP)
        , sock(aSock)
        , cookie(aCookie)
    {
    }

    void    handshakeICY(Channel::SRC_TYPE, bool);
    void    handshakeHTTP(bool);
    void    handshakeJRPC();
    void    handshakeCMD(char *);
    bool    handshakeAuth(const char *, bool);
    void    handshakePLS(ChanHitList **, int, bool);
    void    handshakePLS(ChanInfo &info, bool doneHandshake, const char* tip);
    bool    handshakeHTTPBasicAuth();
    void    handshakeXML();

    void    handshakeRemoteFile(const char *);
    void    handshakeLocalFile(const char *);

    Servent* servent;
    HTTP& http;
    ClientSocket*& sock;
    Cookie& cookie;

private:

    void handshakeGET(char *fn);
    void handshakePOST(char *fn);
    void handshakePCP();
    void handshakeICE(char *in, bool isHTTP);
    void handshakeGIV(char *in);
    void handshakePeerCast();
    void handshakeShoutCast(bool isHTTP);
    void handshakeAdminCGI(char *fn);

    void CMD_redirect(char *cmd, char jumpStr[]);
    void CMD_viewxml(char *cmd, char jumpStr[]);
    void CMD_clearlog(char *cmd, char jumpStr[]);
    void CMD_save(char *cmd, char jumpStr[]);
    void CMD_reg(char *cmd, char jumpStr[]);
    void CMD_edit_bcid(char *cmd, char jumpStr[]);
    void CMD_add_bcid(char *cmd, char jumpStr[]);
    void CMD_apply(char *cmd, char jumpStr[]);
    void CMD_fetch(char *cmd, char jumpStr[]);
    void CMD_stopserv(char *cmd, char jumpStr[]);
    void CMD_hitlist(char *cmd, char jumpStr[]);
    void CMD_clear(char *cmd, char jumpStr[]);
    void CMD_upgrade(char *cmd, char jumpStr[]);
    void CMD_connect(char *cmd, char jumpStr[]);
    void CMD_shutdown(char *cmd, char jumpStr[]);
    void CMD_stop(char *cmd, char jumpStr[]);
    void CMD_bump(char *cmd, char jumpStr[]);
    void CMD_keep(char *cmd, char jumpStr[]);
    void CMD_relay(char *cmd, char jumpStr[]);
    void CMD_net_add(char *cmd, char jumpStr[]);
    void CMD_logout(char *cmd, char jumpStr[]);
    void CMD_login(char *cmd, char jumpStr[]);
};

#endif
