using System;
using System.Globalization;
using System.Text;

namespace PWDTK_DOTNETSTANDARD
{
	public static class HexConverter
    {
		public static byte[] FromHexStringToByteArray(string value)
		{
			var chars = value.ToCharArray();
			var N = chars.Length;
			var buffer = new byte[N / 2 + N % 2];

			// byte array is made up of pairs of "nibbles", 4 bits each, so we must have an even number
			//if (N % 2 != 0)
			//	throw new ArgumentException(value);

			var bufferIndex = 0;
			for (var i = 0; i < N - 1; i += 2)
			{
				buffer[bufferIndex] = FromHex(chars[i]);
				buffer[bufferIndex] <<= 4;
				buffer[bufferIndex] += FromHex(chars[i + 1]);
				bufferIndex++;
			}
			return buffer;
		}

		static byte FromHex(char hexDigit)
		{
			try
			{
				return byte.Parse(
					hexDigit.ToString(),
					NumberStyles.HexNumber,
					CultureInfo.InvariantCulture
				);
			}
			catch (FormatException)
			{
				throw new FormatException("TODO: stuff");
			}
		}

		public static string FromByteArrayToHexString(byte[] value)
		{
			var sb = new StringBuilder();
			sb.Length = 0;
			foreach (byte b in value)
				sb.Append(b.ToString("X2"));
			return sb.ToString();
		}
	}
}
