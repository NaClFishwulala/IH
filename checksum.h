unsigned short checksum1(unsigned short* buffer, unsigned int size)
{
    unsigned long cksum = 0;
    while(size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size)
    {
        cksum += *(unsigned char*)buffer;
    }
    while(cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    return(unsigned short) (~cksum);
}
unsigned short checksum2(unsigned char* buffer, unsigned char* key, unsigned int size)
{
    unsigned short cksum = 0;
    unsigned char i = 0;
    for (i = 0; i < 6; i++) {
        cksum += *(unsigned char*)buffer;
        buffer++;
    }
    buffer = buffer + 8;
    for (i = 0; i < 8; i++) {
        cksum += *(unsigned char*)buffer;
        buffer++;
    }
    buffer = key;
    for (i = 0; i < 16; i++) {
        cksum += *(unsigned char*)buffer;
        buffer++;
    }
    return cksum;
}
