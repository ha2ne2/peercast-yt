#ifndef _MKV_H
#define _MKV_H

#include "stream.h"
#include "channel.h"
#include "matroska.h"

// ----------------------------------------------
class MKVStream : public ChannelStream
{
public:
    MKVStream()
    {
    }
    void readHeader(Stream &, Channel *) override;
    int  readPacket(Stream &, Channel *) override;
    void readEnd(Stream &, Channel *) override;

    void sendPacket(ChanPacket::TYPE, const matroska::byte_string& data, Channel*);
};

#endif