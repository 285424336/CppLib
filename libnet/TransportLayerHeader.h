#ifndef TRANSPORT_LAYER_HEADER_H_INCLUDED
#define TRANSPORT_LAYER_HEADER_H_INCLUDED

#include "NetBase.h"

class TransportLayerHeader : public NetBase
{
public:
    TransportLayerHeader() : NetBase(){}

    /* Returns source port. */
    virtual unsigned short GetSourcePort() const = 0;

    /* Sets source port. */
    virtual void SetSourcePort(unsigned short val) = 0;

    /* Returns destination port. */
    virtual unsigned short GetDestinationPort() const = 0;

    /* Sets destination port. */
    virtual void SetDestinationPort(unsigned short val) = 0;

    /* Sets checksum. */
    virtual void SetSum() = 0;

};


#endif
