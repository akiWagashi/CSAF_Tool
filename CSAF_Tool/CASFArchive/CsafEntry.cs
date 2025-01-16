

namespace CSAF_Tool.CASFArchive;
internal class CsafEntry
{
    public string Name = string.Empty;

    public int StartChunkIndex; //start offset = the value * 0x1000

    public int Size;

}

