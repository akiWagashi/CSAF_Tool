
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Numerics;

namespace CSAF_Tool.Util;
public class IncrementalMD5
{
	public const int BlockSize = 64;

	private static readonly ImmutableArray<ImmutableArray<uint>> S =
	[
	   [7, 12, 17, 22],
	   [5, 9, 14, 20],
	   [4, 11, 16, 23],
	   [6, 10, 15, 21]
	];

	private static readonly ImmutableArray<uint> T =
	[
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	];

	private static readonly ImmutableArray<byte> Padding = 
	[ 
	  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
	  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	];

	public static readonly ImmutableArray<uint> DefaultState = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

	public uint[] State { get; private set; } = DefaultState.ToArray();

	public uint[] Count { get; private set; } = new uint[2];

	private byte[] Digest { get; set; } = new byte[16];

	private byte[] Buffer { get; set; } = new byte[BlockSize];

	public IncrementalMD5()
	{
		Reset();
	}

	public IncrementalMD5(uint[] state, uint[] count)
	{
		if (state.Length == 4)
		{
			state.CopyTo(State, 0);
		}

		if (count.Length == 2)
		{
			count.CopyTo(Count, 0);
		}

	}
	public void Reset()
	{
		State = DefaultState.ToArray();

		Array.Fill<uint>(Count, 0);

		Array.Fill<byte>(Digest, 0);

		Array.Fill<byte>(Digest, 0);
	}

	public ReadOnlySpan<byte> FinalHash()
	{

		byte[] bits = new byte[8];

		Encode(bits, Count);

		uint index = (Count[0] >> 3) % 64;

		uint padLen = (index < 56) ? (56 - index) : (120 - index);

		Update(Padding.ToArray().AsSpan(0, (int)padLen));

		Update(bits);

		Encode(Digest, State);

		return Digest;

	}

	public void Update(ReadOnlySpan<byte> data)
	{
		uint index = (Count[0] >> 3) % BlockSize;

		uint addBit = (uint)data.Length << 3;

		Count[0] += addBit;

		if (Count[0] < addBit) Count[1]++;

		Count[1] += ((uint)data.Length >> 29);

		uint firstPart = 64 - index;

		uint i = 0;

		if (data.Length >= firstPart)
		{
			data.Slice((int)i, (int)firstPart).CopyTo(Buffer.AsSpan((int)index));
			Transform(Buffer);

			for (i = firstPart; i + BlockSize <= data.Length; i += BlockSize)
			{
				Transform(data.Slice((int)i));
			}

			index = 0;
		}

		data.Slice((int)i, (int)(data.Length - i)).CopyTo(Buffer.AsSpan((int)index));

	}

	private void Transform(ReadOnlySpan<byte> data)
	{
		uint a = State[0], b = State[1], c = State[2], d = State[3];
		uint[] x = new uint[16];

		Decode(x, data);

		FF(ref a, b, c, d, x[0], S[0][0], T[0]);
		FF(ref d, a, b, c, x[1], S[0][1], T[1]);
		FF(ref c, d, a, b, x[2], S[0][2], T[2]);
		FF(ref b, c, d, a, x[3], S[0][3], T[3]);
		FF(ref a, b, c, d, x[4], S[0][0], T[4]);
		FF(ref d, a, b, c, x[5], S[0][1], T[5]);
		FF(ref c, d, a, b, x[6], S[0][2], T[6]);
		FF(ref b, c, d, a, x[7], S[0][3], T[7]);
		FF(ref a, b, c, d, x[8], S[0][0], T[8]);
		FF(ref d, a, b, c, x[9], S[0][1], T[9]);
		FF(ref c, d, a, b, x[10], S[0][2], T[10]);
		FF(ref b, c, d, a, x[11], S[0][3], T[11]);
		FF(ref a, b, c, d, x[12], S[0][0], T[12]);
		FF(ref d, a, b, c, x[13], S[0][1], T[13]);
		FF(ref c, d, a, b, x[14], S[0][2], T[14]);
		FF(ref b, c, d, a, x[15], S[0][3], T[15]);

		GG(ref a, b, c, d, x[1], S[1][0], T[16]);
		GG(ref d, a, b, c, x[6], S[1][1], T[17]);
		GG(ref c, d, a, b, x[11], S[1][2], T[18]);
		GG(ref b, c, d, a, x[0], S[1][3], T[19]);
		GG(ref a, b, c, d, x[5], S[1][0], T[20]);
		GG(ref d, a, b, c, x[10], S[1][1], T[21]);
		GG(ref c, d, a, b, x[15], S[1][2], T[22]);
		GG(ref b, c, d, a, x[4], S[1][3], T[23]);
		GG(ref a, b, c, d, x[9], S[1][0], T[24]);
		GG(ref d, a, b, c, x[14], S[1][1], T[25]);
		GG(ref c, d, a, b, x[3], S[1][2], T[26]);
		GG(ref b, c, d, a, x[8], S[1][3], T[27]);
		GG(ref a, b, c, d, x[13], S[1][0], T[28]);
		GG(ref d, a, b, c, x[2], S[1][1], T[29]);
		GG(ref c, d, a, b, x[7], S[1][2], T[30]);
		GG(ref b, c, d, a, x[12], S[1][3], T[31]);

		HH(ref a, b, c, d, x[5], S[2][0], T[32]);
		HH(ref d, a, b, c, x[8], S[2][1], T[33]);
		HH(ref c, d, a, b, x[11], S[2][2], T[34]);
		HH(ref b, c, d, a, x[14], S[2][3], T[35]);
		HH(ref a, b, c, d, x[1], S[2][0], T[36]);
		HH(ref d, a, b, c, x[4], S[2][1], T[37]);
		HH(ref c, d, a, b, x[7], S[2][2], T[38]);
		HH(ref b, c, d, a, x[10], S[2][3], T[39]);
		HH(ref a, b, c, d, x[13], S[2][0], T[40]);
		HH(ref d, a, b, c, x[0], S[2][1], T[41]);
		HH(ref c, d, a, b, x[3], S[2][2], T[42]);
		HH(ref b, c, d, a, x[6], S[2][3], T[43]);
		HH(ref a, b, c, d, x[9], S[2][0], T[44]);
		HH(ref d, a, b, c, x[12], S[2][1], T[45]);
		HH(ref c, d, a, b, x[15], S[2][2], T[46]);
		HH(ref b, c, d, a, x[2], S[2][3], T[47]);

		II(ref a, b, c, d, x[0], S[3][0], T[48]);
		II(ref d, a, b, c, x[7], S[3][1], T[49]);
		II(ref c, d, a, b, x[14], S[3][2], T[50]);
		II(ref b, c, d, a, x[5], S[3][3], T[51]);
		II(ref a, b, c, d, x[12], S[3][0], T[52]);
		II(ref d, a, b, c, x[3], S[3][1], T[53]);
		II(ref c, d, a, b, x[10], S[3][2], T[54]);
		II(ref b, c, d, a, x[1], S[3][3], T[55]);
		II(ref a, b, c, d, x[8], S[3][0], T[56]);
		II(ref d, a, b, c, x[15], S[3][1], T[57]);
		II(ref c, d, a, b, x[6], S[3][2], T[58]);
		II(ref b, c, d, a, x[13], S[3][3], T[59]);
		II(ref a, b, c, d, x[4], S[3][0], T[60]);
		II(ref d, a, b, c, x[11], S[3][1], T[61]);
		II(ref c, d, a, b, x[2], S[3][2], T[62]);
		II(ref b, c, d, a, x[9], S[3][3], T[63]);

		State[0] += a;
		State[1] += b;
		State[2] += c;
		State[3] += d;

	}

	private void Decode(Span<uint> output, ReadOnlySpan<byte> input)
	{
		for (int i = 0; i < output.Length; i++)
		{
			output[i] = BinaryPrimitives.ReadUInt32LittleEndian(input.Slice(i * 4, 4));
		}
	}

	private static void Encode(Span<byte> output, ReadOnlySpan<uint> input)
	{
		for (int i = 0; i < input.Length; i++)
		{
			BinaryPrimitives.WriteUInt32LittleEndian(output.Slice(i * 4, 4), input[i]);
		}
	}

	private void FF(ref uint a, uint b, uint c, uint d, uint x, uint s, uint ac)
	{
		a = BitOperations.RotateLeft(a + F(b, c, d) + x + ac, (int)s) + b;
	}

	private void GG(ref uint a, uint b, uint c, uint d, uint x, uint s, uint ac)
	{
		a = BitOperations.RotateLeft(a + G(b, c, d) + x + ac, (int)s) + b;
	}

	private void HH(ref uint a, uint b, uint c, uint d, uint x, uint s, uint ac)
	{
		a = BitOperations.RotateLeft(a + H(b, c, d) + x + ac, (int)s) + b;
	}

	private void II(ref uint a, uint b, uint c, uint d, uint x, uint s, uint ac)
	{
		a = BitOperations.RotateLeft(a + I(b, c, d) + x + ac, (int)s) + b;
	}

	private uint F(uint x, uint y, uint z)
	{
		return (x & y) | (~x & z);
	}

	private uint G(uint x, uint y, uint z)
	{
		return (x & z) | (y & ~z);
	}

	private uint H(uint x, uint y, uint z)
	{
		return x ^ y ^ z;
	}

	private uint I(uint x, uint y, uint z)
	{
		return y ^ (x | ~z);
	}
}

