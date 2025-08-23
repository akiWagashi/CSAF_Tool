
using CSAF_Tool.Util;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;

namespace CSAF_Tool.CSAFArchive;
public static class Csaf
{
    public static readonly byte[] HeaderSignarture = { 0x43, 0x53, 0x41, 0x46 };

    //private static readonly byte[] DefaultKey = { 0x60, 0x21, 0x7D, 0xC6, 0x5E, 0x7B, 0x5D, 0x67, 0xA6, 0x51, 0xEA, 0x9B, 0x30, 0x54, 0xEA, 0x36,
    //                                              0x0C, 0xD5, 0x62, 0x6E, 0xFA, 0xB8, 0x68, 0x6C, 0xD5, 0x87, 0xE7, 0x7B, 0x9C, 0xA3, 0x92, 0x40  };

    private static readonly byte[] DefaultKey = { 0xF5, 0x96, 0x4B, 0x37, 0xA6, 0x80, 0x10, 0x53, 0x2B, 0x6A, 0x1A, 0x8D, 0x1A, 0xA3, 0x07, 0x73,
                                                  0x3A, 0x25, 0x61, 0x37, 0xE4, 0x52, 0x8F, 0xE5, 0x2F, 0x32, 0xD2, 0xA2, 0x05, 0x58, 0x5A, 0x27 }; //夏幻の恋

    private static readonly byte[] AesIV = { 0x46, 0x61, 0x6D, 0x69, 0x6C, 0x79, 0x41, 0x64, 0x76, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x20 };  //FamilyAdvSystem

    public static void ExtractResource(string sourceArchive, string outputPath)
    {
        using FileStream fileStream = File.OpenRead(sourceArchive);

        using BinaryReader sourceReader = new BinaryReader(fileStream);

        ExtractResource(sourceReader, outputPath);

    }

    private static void ExtractResource(BinaryReader sourceReader, string outputPath)
    {
        var header = sourceReader.ReadBytes(HeaderSignarture.Length);

        if (!HeaderSignarture.SequenceEqual(header)) throw new Exception("File format mismatch");

        CsafFlag casfFlag = (CsafFlag)sourceReader.ReadUInt32();

        if (!casfFlag.HasFlag(CsafFlag.ArchiveEnable)) throw new Exception("The archive is disable");

        var entryCount = sourceReader.ReadUInt32(); //maybe

        var infoSectionSize = entryCount * 24 + 0x1F;
        infoSectionSize &= 0xFFFFF000;
        infoSectionSize += 0xFE0;

        var catalogSize = sourceReader.ReadUInt32();

        sourceReader.ReadBytes(0x10);   //this is md5 of info section + (decrypted) entryname section

        byte[] catalogBuffer = sourceReader.ReadBytes((int)(infoSectionSize + catalogSize));  //read info section and entryname section

        var infoSection = catalogBuffer.AsSpan(0, (int)infoSectionSize);

        var entryNameSection = catalogBuffer.AsSpan((int)infoSectionSize);

        if (casfFlag.HasFlag(CsafFlag.DataEncrypt)) 
        {
            DecryptData(entryNameSection, 0).CopyTo(entryNameSection);
        } 

        var entries = ParseCatalog(infoSection, entryNameSection, (int)entryCount); //parse info to entry

        const int chunkSize = 0x1000;   //the maximum read at each time
        int extractCount = 0;
        List<Task> tasks = new List<Task>((int)entryCount);

        foreach (var entry in entries)  //extract resource
        {

            var chunkIndex = entry.StartChunkIndex;

            sourceReader.BaseStream.Position = chunkIndex << 0xC;   //offset * 0x1000

            var remainingLength = entry.Size;

            var paddingSize = entry.Size.NumberPadding(chunkSize);

            var data = sourceReader.ReadBytes(paddingSize);     //read resouce data

            var chunkCount = paddingSize / chunkSize;

            var task = Task.Run(() =>
            {

                if (casfFlag.HasFlag(CsafFlag.DataEncrypt)) 
                {
                    for (int i = 0; i < chunkCount; i++)
                    {
                        DecryptData(data.AsSpan(i * chunkSize, chunkSize), chunkIndex + i).CopyTo(data, i * chunkSize);   //decrypt resource data , maximum of 0x1000 bytes at each time
                    }
                } 

                string createFileName = Path.Combine(outputPath, entry.Name);

                string directoryName = Path.GetDirectoryName(createFileName) ?? throw new Exception("Path.GetDirectoryName return null");

                if (!Directory.Exists(directoryName)) Directory.CreateDirectory(directoryName);


                using (FileStream fileStream = File.Create(createFileName))
                {
                    fileStream.Write(data, 0, entry.Size);
                    fileStream.Flush();
                }

                Interlocked.Increment(ref extractCount);


            }).ContinueWith(task =>
            {
                if (task.IsFaulted)
                {
                    Console.WriteLine($"ERROR ：resource : {entry.Name} extract failed , because {task.Exception.Message}");
                }
                else
                {
                    Console.WriteLine($"MESSAGE : extract resource : {entry.Name}");
                }
            });

            tasks.Add(task);
        }

        Task.WaitAll(tasks.ToArray());

        Console.WriteLine($"MESSAGE : extract {extractCount}/{entryCount} files from archive");

    }

    private static byte[] DecryptData(Span<byte> encryptedData, int dataOffset)
    {
        byte[] aesKey = new byte[0x20];
        int startIndex = (dataOffset >> 3) % 0x10;

        #region init aes key

        var md5 = new IncrementalMD5();

        Span<byte> defaultKeyView = DefaultKey.AsSpan(0, 0x10);
        Span<byte> aesKeyView = aesKey.AsSpan(0, 0x10);

        for (int i = 0; i < 0x10; i++) 
        {
            aesKeyView[i] = defaultKeyView[(startIndex + i) % 0x10].RotateLeft(dataOffset);
        } 

        md5.Update(aesKeyView);
        md5.FinalHash().CopyTo(aesKeyView);

        defaultKeyView = DefaultKey.AsSpan(0x10, 0x10);
        aesKeyView = aesKey.AsSpan(0x10, 0x10);

        for (int i = 0; i < 0x10; i++) 
        {
            aesKeyView[i] = defaultKeyView[(startIndex + i) % 0x10].RotateLeft(dataOffset);
        }

        md5.Update(aesKeyView);
        md5.FinalHash().CopyTo(aesKeyView);

        #endregion

        using Aes aesDecrpytor = Aes.Create();

        aesDecrpytor.KeySize = 256;

        aesDecrpytor.Key = aesKey;

        return aesDecrpytor.DecryptCbc(encryptedData, AesIV, PaddingMode.Zeros);

    }

    private static ReadOnlyCollection<CsafEntry> ParseCatalog(ReadOnlySpan<byte> infoBuffer, ReadOnlySpan<byte> fileNameBuffer, int catalogSize)
    {
        List<CsafEntry> catalog = new(catalogSize);

        int infoBufferIndex = 0;

        int fileNameBufferIndex = 0;

        for (int i = 0; i < catalogSize; i++)
        {
            infoBufferIndex += 0x10;

            CsafEntry entryInfo = new CsafEntry();

            entryInfo.StartChunkIndex = BitConverter.ToInt32(infoBuffer.Slice(infoBufferIndex, 4));
            entryInfo.Size = BitConverter.ToInt32(infoBuffer.Slice(infoBufferIndex + 4, 4));

            int entryNameLength = fileNameBuffer.GetCStyleStringLength(fileNameBufferIndex);
            entryInfo.Name = Encoding.Unicode.GetString(fileNameBuffer.Slice(fileNameBufferIndex, entryNameLength));

            infoBufferIndex += 8;
            fileNameBufferIndex += entryNameLength;
            fileNameBufferIndex += 10;

            catalog.Add(entryInfo);

        }

        return catalog.AsReadOnly();

    }

}

