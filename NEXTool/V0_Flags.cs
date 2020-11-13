using System;

namespace CyuNEX.PRUDP
{
    [Flags]
    enum V0_Flags
    {
        FLAG_ACK = 0x001,
        FLAG_RELIABLE = 0x002,
        FLAG_NEED_ACK = 0x004,
        FLAG_HAS_SIZE = 0x008,
        FLAG_MULTI_ACK = 0x200
    }
}
