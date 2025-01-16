
using System.Runtime.InteropServices;

namespace CSAF_Tool.Util;
internal static class Extension
{
    public static byte RotateLeft(this byte x, int n)
    {
        return (byte)((x << n) | (x >> (8 - n)));
    }

    public static int NumberPadding(this int x, int multiple)
    {
        if (x % multiple == 0) return x;

        return ((x / multiple) + 1) * multiple;
    }

    public static int GetCStyleStringLength(this ReadOnlySpan<byte> buufer, int startIndex = 0)
    {
        var index = MemoryMarshal.Cast<byte, UInt16>(buufer.Slice(startIndex)).IndexOf((ushort)0);

        return index == -1 ? -1 : index * 2;
    }

}

