// ------------------------------------------------
// File : servhs.cpp
// Date: 4-apr-2002
// Author: giles
// Desc:
//      Servent handshaking, TODO: should be in its own class
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


#include "incoming.h"
#include "servent.h"
#include "servmgr.h"

// -----------------------------------
void Servent::handshakeIncoming()
{
    setStatus(S_HANDSHAKE);

    char buf[1024];
    sock->readLine(buf, sizeof(buf));

    char sb[64];
    sock->host.toStr(sb);

    if (stristr(buf, RTSP_PROTO1))
    {
        LOG_DEBUG("RTSP from %s '%s'", sb, buf);
        RTSP rtsp(*sock);
        rtsp.initRequest(buf);
        handshakeRTSP(rtsp);
    }else
    {
        bool isHTTP;
        if (stristr(buf, HTTP_PROTO1))
        {
            LOG_DEBUG("HTTP from %s '%s'", sb, buf);
            isHTTP = true;
        }else
        {
            LOG_DEBUG("Connect from %s '%s'", sb, buf);
            isHTTP = false;
        }
        HTTP http(*sock);
        http.initRequest(buf);
        IncomingController controller(this, sock, http, cookie);
        controller.handshakeHTTP(isHTTP);
    }
}

// -----------------------------------
bool Servent::canStream(Channel *ch)
{
    if (ch==NULL)
        return false;

    if (servMgr->isDisabled)
        return false;

    if (!isPrivate())
    {
        if  (
                servMgr->bitrateFull(ch->getBitrate())
                || ((type == T_RELAY) && servMgr->relaysFull())
                || ((type == T_DIRECT) && servMgr->directFull())
                || !ch->isPlaying()
                || ch->isFull()
            )
            return false;
    }

    return true;
}

// -----------------------------------
void Servent::triggerChannel(char *str, ChanInfo::PROTOCOL proto, bool relay)
{
    ChanInfo info;

    servMgr->getChannel(str, info, relay);

    if (proto == ChanInfo::SP_PCP)
        type = T_RELAY;
    else
        type = T_DIRECT;

    outputProtocol = proto;

    processStream(false, info);
}

// -----------------------------------
// Warning: testing RTSP/RTP stuff below.
// .. moved over to seperate app now.
// -----------------------------------
void Servent::handshakePOST()
{
    char tmp[1024];
    while (sock->readLine(tmp, sizeof(tmp)))
        LOG_DEBUG("POST: %s", tmp);

    throw HTTPException(HTTP_SC_BADREQUEST, 400);
}

// -----------------------------------
void Servent::handshakeRTSP(RTSP &rtsp)
{
    throw HTTPException(HTTP_SC_BADREQUEST, 400);
}

// -----------------------------------
bool Servent::getLocalURL(char *str)
{
    if (!sock)
        throw StreamException("Not connected");

    char ipStr[64];
    Host h;

    if (sock->host.localIP())
        h = sock->getLocalHost();
    else
        h = servMgr->serverHost;

    h.port = servMgr->serverHost.port;

    h.toStr(ipStr);

    sprintf(str, "http://%s", ipStr);
    return true;
}

// -----------------------------------
void Servent::readICYHeader(HTTP &http, ChanInfo &info, char *pwd, size_t plen)
{
    char *arg = http.getArgStr();
    if (!arg) return;

    if (http.isHeader("x-audiocast-name") || http.isHeader("icy-name") || http.isHeader("ice-name"))
    {
        info.name.set(arg, String::T_ASCII);
        info.name.convertTo(String::T_UNICODE);

    }else if (http.isHeader("x-audiocast-url") || http.isHeader("icy-url") || http.isHeader("ice-url"))
        info.url.set(arg, String::T_ASCII);
    else if (http.isHeader("x-audiocast-bitrate") || (http.isHeader("icy-br")) || http.isHeader("ice-bitrate") || http.isHeader("icy-bitrate"))
        info.bitrate = atoi(arg);
    else if (http.isHeader("x-audiocast-genre") || http.isHeader("ice-genre") || http.isHeader("icy-genre"))
    {
        info.genre.set(arg, String::T_ASCII);
        info.genre.convertTo(String::T_UNICODE);

    }else if (http.isHeader("x-audiocast-description") || http.isHeader("ice-description"))
    {
        info.desc.set(arg, String::T_ASCII);
        info.desc.convertTo(String::T_UNICODE);

    }else if (http.isHeader("Authorization")) {
        if (pwd)
            http.getAuthUserPass(NULL, pwd, 0, plen);
    }
    else if (http.isHeader(PCX_HS_CHANNELID))
        info.id.fromStr(arg);
    else if (http.isHeader("ice-password"))
    {
        if (pwd)
            if (strlen(arg) < 64)
                strcpy(pwd, arg);
    }else if (http.isHeader("content-type"))
    {
        if (stristr(arg, MIME_OGG))
            info.contentType = ChanInfo::T_OGG;
        else if (stristr(arg, MIME_XOGG))
            info.contentType = ChanInfo::T_OGG;

        else if (stristr(arg, MIME_MP3))
            info.contentType = ChanInfo::T_MP3;
        else if (stristr(arg, MIME_XMP3))
            info.contentType = ChanInfo::T_MP3;

        else if (stristr(arg, MIME_WMA))
            info.contentType = ChanInfo::T_WMA;
        else if (stristr(arg, MIME_WMV))
            info.contentType = ChanInfo::T_WMV;
        else if (stristr(arg, MIME_ASX))
            info.contentType = ChanInfo::T_ASX;

        else if (stristr(arg, MIME_NSV))
            info.contentType = ChanInfo::T_NSV;
        else if (stristr(arg, MIME_RAW))
            info.contentType = ChanInfo::T_RAW;

        else if (stristr(arg, MIME_MMS))
            info.srcProtocol = ChanInfo::SP_MMS;
        else if (stristr(arg, MIME_XPCP))
            info.srcProtocol = ChanInfo::SP_PCP;
        else if (stristr(arg, MIME_XPEERCAST))
            info.srcProtocol = ChanInfo::SP_PEERCAST;

        else if (stristr(arg, MIME_XSCPLS))
            info.contentType = ChanInfo::T_PLS;
        else if (stristr(arg, MIME_PLS))
            info.contentType = ChanInfo::T_PLS;
        else if (stristr(arg, MIME_XPLS))
            info.contentType = ChanInfo::T_PLS;
        else if (stristr(arg, MIME_M3U))
            info.contentType = ChanInfo::T_PLS;
        else if (stristr(arg, MIME_MPEGURL))
            info.contentType = ChanInfo::T_PLS;
        else if (stristr(arg, MIME_TEXT))
            info.contentType = ChanInfo::T_PLS;
    }
}

