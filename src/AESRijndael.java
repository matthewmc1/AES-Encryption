public class AESRijndael {

// Antal runder
final int rounds = 10;

// Pointer ind i ExpandedKey. 
public int ExpandedKeyP = 0;

public byte[] state = new byte[16];

public byte[] key = new byte[16]; 

byte[] Sbox = new byte[256];
byte[] invSbox = new byte[256];
byte[] ExpandedKey = new byte[16 * (10 + 1)];

	private void SubBytes() {
		for (int i = 0 ; i < 16 ; i++) {
			state[i] = Sbox[ ToInt(state[i])];
		}
	}
	
	private void InvSubBytes() {
		for (int i = 0 ; i < 16 ; i++) {
			state[i] = invSbox[ ToInt(state[i])];
		}
	}
	
	private byte SubByte(byte a) {
		return Sbox[ToInt(a)];
	}
	
	// Da det i denne implementation altid gælder at nøglen er mindre end 192 bit, har jeg
	// kun implementeret den ene af KeyExpansion-funktionerne.	
	private void ExpandKey() {
		byte[] tmp = new byte[5]; // Den 5. byte bruges som en imidlertid variabel.
		byte[] Rcon = new byte[12];
		Rcon[1] = 0x01;
		for (int i = 2 ; i < 12 ; i++) {
			Rcon[i] = XTime(Rcon[i-1]);
		}
		
		// Kopier cipher-key ind i de første 4 words af expandedkey.
		for (int i = 0 ; i < 16 ; i++)
			ExpandedKey[i] = key[i];
			
		for (int i = 4 ; i < 4 * (10 + 1) ; i++) { // Itererer words, ikke bytes. 
			for (int j = 0 ; j < 4 ; j++)
				tmp[j] = ExpandedKey[4*(i-1) + j];
					
			if ( (i % 4) == 0) {
				// RotWord
				tmp[4] = tmp[0];
				for (int j = 0 ; j < 4; j++)
					tmp[j] = tmp[j+1];

				// SubWord
				for (int j = 0 ; j < 4; j++)
					tmp[j] = SubByte(tmp[j]);

				tmp[0] = (byte)(tmp[0] ^ Rcon[i / 4]);
			}
			
			for (int j = 0 ; j < 4; j++)
				ExpandedKey[4*i + j] = (byte)(ExpandedKey[4*(i - 4) + j] ^ tmp[j]);
		}
	}
	
	// Debug-metode; Bruges til let at udskrive et array på 4 bytes.
	public static void WriteWord(String desc, byte[] w) {
		MSG(desc + ": ");
		for (int i = 0 ; i < 4 ; i++) {
			MSG(Byte2Hex(w[i]) + " ");
		}
		MSG("\n");
	}
	
	private void InvShiftRows() {
		byte tmp;
		// Række 1
		tmp = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = tmp;
		// Række 2
		tmp = state[14]; state[14] = state[6]; state[6] = tmp;
		tmp = state[10]; state[10] = state[2]; state[2] = tmp;
		// Række 3
		tmp = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = tmp;
	}
	
	private void ShiftRows() {
		byte tmp;
		// Række 1
		tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
		// Række 2
		tmp = state[14]; state[14] = state[6]; state[6] = tmp; 
		tmp = state[10]; state[10] = state[2]; state[2] = tmp;
		// Række 3
		tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;
	}
	
	// Kan udskrive klassens tabeller.
	public void PrintState() {
		String[] tmp = {"","","",""};
		for (int i = 0 ; i < 16 ; i++) {
			tmp[i % 4] += Byte2Hex(state[i]) + " ";
		}	
		for (int i = 0 ; i  < 4 ; i++)
			System.out.println(tmp[i]);		
	}

	public void PrintKey() {
		String[] tmp = {"","","",""};
		for (int i = 0 ; i < 16 ; i++) {
			tmp[i % 4] += Byte2Hex(key[i]) + " ";
		}	
		for (int i = 0 ; i  < 4 ; i++)
			System.out.println(tmp[i]);		
	}

	public void PrintExpandedKey() {
		for (int i = 0 ; i < 176 ; i++) {
			System.out.print("" + Byte2Hex(ExpandedKey[i]) + " ");
			if ( (i % 16 ) == 15)
				MSG("\n");
		}
	}

	private void MixColumns() {
		byte[] tmp = new byte[4]; // Kan indeholde en søjle.
		for (int i = 0 ; i < 4 ; i++) { // Itererer igennem søjlerne. 
			// Følgende er implementeret som beskrevet i [1] sektion 5.1.3.
			tmp[0] = (byte)(PolyMult((byte)0x02, state[i*4]) ^ PolyMult((byte)0x03, state[i*4+1]) ^ state[i*4+2] ^ state[i*4+3]);
			tmp[1] = (byte)(state[4*i] ^ PolyMult((byte) 0x02, state[4*i+1]) ^ PolyMult((byte) 0x03, state[4*i+2]) ^ state[4*i+3]);
			tmp[2] = (byte)(state[4*i] ^ state[4*i+1] ^ PolyMult((byte)0x02, state[4*i+2]) ^ PolyMult((byte)0x03,state[4*i+3]));
			tmp[3] = (byte)(PolyMult((byte)0x03, state[4*i]) ^ state[4*i+1] ^ state[4*i+2] ^ PolyMult((byte)0x02,state[4*i+3]));
			for (int j = 0 ; j < 4; j++)
				state[4*i+j] = tmp[j];
		}
	}
	
	private void InvMixColumns() {
		byte[] tmp = new byte[4];
		for (int i = 0 ; i < 4 ; i++) {
			// Følgende er implementeret som beskrevet i [1] sektion 5.3.3
			tmp[0] = (byte)(PolyMult((byte)0x0e, state[4*i]) ^ PolyMult((byte) 0x0b, state[4*i+1]) 
					 ^ PolyMult((byte)0x0d, state[4*i+2]) ^ PolyMult((byte)0x09, state[4*i+3]));
			tmp[1] = (byte)(PolyMult((byte)0x09, state[4*i]) ^ PolyMult((byte) 0x0e, state[4*i+1]) 
					 ^ PolyMult((byte)0x0b, state[4*i+2]) ^ PolyMult((byte)0x0d, state[4*i+3]));
			tmp[2] = (byte)(PolyMult((byte)0x0d, state[4*i]) ^ PolyMult((byte) 0x09, state[4*i+1]) 
					 ^ PolyMult((byte)0x0e, state[4*i+2]) ^ PolyMult((byte)0x0b, state[4*i+3]));
			tmp[3] = (byte)(PolyMult((byte)0x0b, state[4*i]) ^ PolyMult((byte) 0x0d, state[4*i+1]) 
					 ^ PolyMult((byte)0x09, state[4*i+2]) ^ PolyMult((byte)0x0e, state[4*i+3]));					 			
			for (int j = 0 ; j < 4; j++)
				state[4*i+j] = tmp[j];
		}
	}

	public static byte XTime(byte a, byte times) {
		for (int i = 0 ; i < times ; i++)
			a = XTime(a);
		return a;
	}
	
	public static byte XTime(byte a) {
		byte b;
		b = (byte)(a << 1);
		
		if ( (a & 128) != 0)
			b = (byte) (b ^ (0x1b));
		return b;
	}

	// Udskriver en byte i binær notation.
	public static void Byte2Bin(byte b) {
		for (int i = 7 ; i >= 0 ; i--)
			if ( (b & (1 << i)) != 0)
				System.out.print("1");
			else
				System.out.print("0");
	}

	// En funktion der udfører multiplikationen af to polynomier, som beskrevet i 
	// [1] sektion 4.2. 
	public static byte PolyMult(byte a, byte b) {
		byte res = 0;
		for (byte i = 7 ; i >= 0 ; i--)
			if ( (a & (1 << i)) != 0 )
				res = (byte)(res ^ XTime(b, i));
		return res;
	}
	
	private void AddRoundKey() {
		for (int i = 0 ; i < 16 ; i++) {
			state[i] = (byte)(state[i] ^ ExpandedKey[ExpandedKeyP]);
			ExpandedKeyP++;
		}
	}
	
	private void InvAddRoundKey() {		
		for (int i = 15 ; i >= 0 ; i--) {
			state[i] = (byte)(state[i] ^ ExpandedKey[ExpandedKeyP]);
			ExpandedKeyP--;
		}		
	}
	
	// Blot lavet for at lette udskrivningen af debug-information til konsollen.
	public static void MSG(String msg) {
		System.out.print(msg);
	}
	
	// Function der viser datatypen byte i hex.
	public static String Byte2Hex(byte b) {
		byte tmp = 0;
		String str="";
		for (int i = 7 ; i > 3 ; i--)
			if ( (b & (1 << i)) != 0)
				tmp = (byte) (tmp |(1 << (i - 4)));
				
		if (tmp < 10) {
			str = str + tmp;
		} else {
			char c = (char)('A' + (tmp - 10));
			str = str + c;
		}
		
		tmp = 0;
		for (int i = 3 ; i > -1 ; i--)
			if ( (b & (1 << i)) != 0)
				tmp = (byte) (tmp |(1 << (i)));
		
		if (tmp < 10)
			str = str + tmp;
		else {
			char c = (char)('A' + (tmp - 10));
			str = str + c;
		}
		return str;
	}
	
	// Lavet for at undgå at skulle bekymre sig om javas mangel på "unsigned byte".
	public static byte ToByte(int a) {
		byte tmp = 0;
		for (int i = 7 ; i >= 0 ; i--)
			if ( (a & (1 <<i)) != 0)
				tmp = (byte)(tmp | (1 << i));			
		return tmp;
	}
		
	public static int ToInt(byte a) {
		int tmp = 0;
		for (int i = 7 ; i >= 0 ; i--)
			if ( (a & (1 <<i)) != 0)
				tmp = tmp | (1 << i);
		return tmp;
	}
	
	public void init() {
		int[] tmpSbox = 
		  { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
			0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
			0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
			0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
			0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
			0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
			0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
			0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
			0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
			0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
			0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
			0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
			0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
			0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
			0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
			0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
		  };
		 
		 int[] tmpinvSbox =
		  {
			0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
			0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,		  	
			0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
			0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
			0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
			0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
			0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
			0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
			0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
			0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
			0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
			0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
			0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
			0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
			0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
			0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
		  };
		
		// Konverterer S-boxene til klassens "eget" byte-format.	
		for (int i = 0 ; i < 256 ; i++) {
			Sbox[i] = ToByte(tmpSbox[i]);
			invSbox[i] = ToByte(tmpinvSbox[i]);			
		}		

		ExpandKey();		
	}
	
	public void decrypt() {			
		init();
		ExpandedKeyP = 175;
		
		InvAddRoundKey();
	
		for (int i = 1 ; i < rounds ; i++) {
			InvShiftRows();
			InvSubBytes();
			InvAddRoundKey();
			InvMixColumns();
		}
		
		InvShiftRows();
		InvSubBytes();
		InvAddRoundKey();
	}
	
	public void encrypt() {				
		init();
		ExpandedKeyP = 0;
		
		AddRoundKey();		
		
		for (int i = 1 ; i < rounds ; i++) {
			SubBytes();
			ShiftRows();
			MixColumns();
			AddRoundKey();
		}
		
		SubBytes();
		ShiftRows();	
		AddRoundKey();
	}

	// Bruges til at konvertere fra int[] til klassens "egne" byte-form.
	public void setIndata(int[] data) {
		for (int i = 0 ; i < 16 ; i++)
			state[i] = ToByte(data[i]);
	}
	
	public void setCipherkey(int[] ckey) {
		for (int i = 0 ; i < 16 ; i++)
			key[i] = ToByte(ckey[i]);	
	}
		
	// Main indeholder debug-eksempler.
	public static void main(String args[]) {		
		AESRijndael aes = new AESRijndael();
		
		// debug-data:
		int[] indata1 = 
			{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31,0x98, 0xa2,0xe0, 0x37, 0x07,0x34}; 
		
		int[] cipherkey1 = 
			{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

		int[] indata2 = 
			{ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		
		int[] cipherkey2 = 
			{ 0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

		aes.setIndata(indata2);
		aes.setCipherkey(cipherkey2);	
		
		aes.MSG("Input:\n");
		aes.PrintState();
				
		aes.encrypt();
		aes.MSG("Encrypted:\n");
		aes.PrintState();
		
		aes.decrypt();
		aes.MSG("Decrypted:\n");
		aes.PrintState();					
	}
}
