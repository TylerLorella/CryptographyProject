/*
 * Cryptography Practical Project
 * Implementation of KMACXOF256 by Maxfield England and Tyler Lorella
 * 
 * Based on the C-implementation of SHA-3 by Markku-Juhani O. Saarinen 
 * https://github.com/mjosaarinen/tiny_sha3
 * 
 */

import java.math.BigInteger;

public class KMACXOF256 {

	//Constants

	//Rount constants (BigInteger) 
	private BigInteger[] RC = new BigInteger[24];

	//String representations of the constants; to populate RC on radix 16
	private String[] toRC = {"0000000000000001", "0000000000008082", "800000000000808A", "8000000080008000",
			"000000000000808B", "0000000080000001", "8000000080008081", "8000000000008009", "000000000000008A",
			"0000000000000088", "0000000080008009", "000000008000000A", "000000008000808B","800000000000008B", "8000000000008089",
			"8000000000008003", "8000000000008002", "8000000000000080", "000000000000800A", "800000008000000A", 
			"8000000080008081", "8000000000008080", "0000000080000001", "8000000080008008"}; 

	//Declaration of 2D array of rotation offsets r[][]; formatted r(x, y) = r[x][y]
	/*int[][] r = {{0, 36, 3, 41, 18},
			{1, 44, 10, 45, 2},
			{62, 6, 43, 15, 61}, 
			{28, 55, 25, 21, 56}, 
			{27, 20, 39, 8, 14}};
	 */

	//Initialize keccak fields and constants
	int[] keccakf_rotc = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
			27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

	int[] keccakf_piln = {10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
			15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};


	BigInteger[] bc = new BigInteger[5];
	BigInteger t;

	BigInteger[] myState = new BigInteger[25]; //each element is a "lane" of the internal state?

	//State instance fields
	//Length of the return we're looking for
	private int mdlen; //message digest length?

	//
	private int rsiz;

	//Keeps track of which bytes have already been operated on in between update steps
	private int pt;


	/**
	 * 
	 * @param k Key
	 * @param m Authenticated data
	 * @param L output byte length
	 * @param S diversification string
	 */
	public KMACXOF256(final BigInteger k, final byte[] m, final int L, final String S) {

		//Set ultimate output length of digest
		mdlen = L;

		sha3_init(mdlen);
		//sha3_update(m.getBytes());
		sha3_update(m);

	}

	/**
	 * Returns KMACXOF256 of given key bitstring (byte array), data, length of desired output,
	 * and diversification string
	 * 
	 * @param K
	 * @param X
	 * @param L
	 * @param S
	 */
	KMACXOF256(byte[] K, byte[] X, int L, String S){

		//Initialize round constants
		for (int i = 0; i < 24; i++) {
			RC[i] = new BigInteger(toRC[i], 16);

			//System.out.println("Number: " + RC[i]);

			byte[] x1 = bytepad(encode_string(K), 168);
			byte[] x3 = right_encode(BigInteger.ZERO);

			byte[] newX = new byte[x1.length + X.length + x3.length];

			int index = 0;
			for (byte b : x1) {
				newX[index] = b;
				index++;
			}
			for (byte b: X) {
				newX[index] = b;
				index++;
			}
			for (byte b: x3) {
				newX[index] = b;
				index++;
			}

			//What does she doooooo//TODO: Integrate
			cSHAKE256(newX, L, "KMAC", S);
		}

		/**
		 * Returns CSHAKE (in terms of Keccak and SHAKE256) of the given goodies
		 * 
		 * @param X
		 * @param L
		 * @param N
		 * @param S
		 * @return
		 */
		byte[] cSHAKE256(byte[] X, int L, String N, String S){

			char[] flex = N.toCharArray();
			byte[] x1 = new byte[flex.length];
			for (int i = 0; i < flex.length; i++){
				x1[i] = (byte)flex[i];
			}
			char[] flex2 = S.toCharArray();
			byte[] x2 = new byte[flex2.length];
			for (int i = 0; i < flex2.length; i++) {
				x2[i] = (byte)flex2[i];
			}

			byte[] n = encode_string(x1);
			byte[] s = encode_string(x2);

			byte[] newX = new byte[x1.length + x2.length];
			int index = 0;
			for (byte b : x1) {
				newX[index] = x1[index];
				index++;
			}

			for (byte b : x2) {
				newX[index] = x2[index];
				index++;
			}

			byte[] retStart = bytepad(newX, 136);

			byte[] ret = new byte[retStart.length + X.length + 2];

			index = 0;
			for (byte b : retStart) {
				ret[index] = retStart[index];
				index++;
			}
			for (byte b : X) {
				ret[index] = X[index];
				index++;
			}
			ret[ret.length-2] = 0;
			ret[ret.length-1] = 0;

			return sha3(ret, L);
		}


		/**
		 * Provides a right-encoded byte array based on the given integer.
		 * @param x The integer to be encoded
		 * @return Returns a byte array based on the given integer, with right-padding of the length.
		 */
		byte[] right_encode(BigInteger x) {

			/*Possibly trivial solution; based on the specifications, 
			 * as the encodes' primary focus is to encode the integer as a byte array, a feature that BigInteger natively 
			 * has.
			 */
			byte[] retBytes = x.toByteArray();
			byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
			byte[] finalBytes = new byte[retBytes.length + addBytes.length];
			for (int i = 0; i < retBytes.length; i++) {
				finalBytes[i] = retBytes[i];
			}
			for (int i = 0; i < addBytes.length; i++) {
				finalBytes[retBytes.length + i] = addBytes[i];
			}
			return finalBytes;

			//Leaving as legacy in case the provided solution is not accurate
			//		ArrayList<Byte> byteArray = new ArrayList<Byte>();
			//
			//		int n = 0;
			//		while (BigInteger.TWO.pow(8*n).compareTo(x) == -1) n++;
			//
			//		for (int i = n; i > 0; i++) {
			//
			//			byte[] currBytes = x.subtract(BigInteger.TWO.pow(8*i)).toByteArray();
			//			for (byte b : currBytes) byteArray.add(b);
			//		}
			//		
			//		byteArray.

		}

		/**
		 * Returns the left encoding of the (big) integer value x, preceded by the bytes of the number size.
		 * @param x the BigInteger to create a byte encoding from
		 * @return Returns the encoding.
		 */
		byte[] left_encode(BigInteger x){

			//Only difference between left_encode and right_encode is that left_encode puts the int size padding
			//at the beginning of the byte array.

			byte[] retBytes = x.toByteArray();
			byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
			byte[] finalBytes = new byte[retBytes.length + addBytes.length];

			for (int i = 0; i < addBytes.length; i++) {
				finalBytes[i] = addBytes[i];
			}

			for (int i = 0; i < retBytes.length; i++) {
				finalBytes[addBytes.length + i] = retBytes[i];
			}

			return finalBytes;

		}

		public byte[] encode_string(byte[] s) {

			byte[] first = left_encode(BigInteger.valueOf(s.length));

			byte[] ret = new byte[first.length + s.length];
			for (int i = 0; i < first.length; i++) {
				ret[i] = first[i];
			}
			for (int i = 0; i < s.length; i++) {
				ret[i+first.length] = s[i];
			}

			return ret;
		}

		//Prepends an encoding of the integer w to the string x, and pads the result
		//with zeros until it is a byte string whose length in bytes is a multiple
		//of w
		//used for encoded strings
		public byte[] bytepad(byte[] X, int w) {

			byte[] z1 = left_encode(BigInteger.valueOf(w));

			byte[] z = new byte[z1.length + X.length];
			for (int i = 0; i < z1.length; i++) {
				z[i] = z1[i];
			}
			for (int i = z1.length; i < z.length; i++) {
				z[i] = X[i];
			}

			int tarLen = z.length;
			int addZeroes = 0;
			while (tarLen + addZeroes % 8 != 0) {
				addZeroes++;
			}
			while ((tarLen + addZeroes) / 8 % w != 0) {
				addZeroes += 8;
			}

			byte[] ret = new byte[tarLen + addZeroes];
			int i;
			for (i = 0; i < ret.length - z.length; i++) {
				ret[i+z.length] = 0;
			}
			for (int x = 0; x < z.length; x++) {
				ret[x] = z[x];
			}

			//		while ((z.length() / 8.0) % w != 0) {
			//			z = z + "00000000";
			//		}

			return z;

		}


		public String getData() {
			byte[] messageDigest = sha3_final();
			//return sha3_final();
			String toReturn = "";
			//for (byte element: messageDigest) toReturn = toReturn + " " + Integer.toBinaryString(element);
			//for (byte element: messageDigest) System.out.println( element );


			for (int index = 0; index < messageDigest.length; index++) {
				//toReturn = toReturn + "byte index: " + index + ", byte String: " + Integer.toBinaryString(messageDigest[index]) + 
				//		", decimal: " + Integer.toUnsignedString(messageDigest[index]) + "\n";
				toReturn = toReturn + "byte index: " + index + ", byte String: " + byte2String(messageDigest[index]) + 
						", decimal: " + Integer.toUnsignedString(messageDigest[index]) + "\n";
			}

			return toReturn;
		}

		//return? where is state changed
		public void keccakf(BigInteger[] state) {

			//For 24 rounds 
			for (int r = 0 ; r < 24; r++) {

				//Theta function
				for (int i = 0; i < 5; i++) { //TODO: cleanup
					try {
						bc[i] = state[i].xor(state[i+5]).xor(state[i+10]).xor(state[i+15]).xor(state[i+20]);
					} catch (Exception e) {
						System.out.println("state i: " + state[i] + ", i = " + i);
						System.out.println("state i+5: " + state[i+5] + ", i = " + i);
						System.out.println("state i+10: " + state[i+10] + ", i = " + i);
						System.out.println("state i+15: " + state[i+15] + ", i = " + i);
						System.out.println("state i+20: " + state[i+20] + ", i = " + i + "\n");
					}
				}

				for (int i = 0; i < 5; i++) {

					t = bc[(i+4) % 5].xor(ROTL64(bc[(i+1) % 5], 1)); 

					for (int j = 0; j < 25; j += 5) {
						state[j + 1] = state[j+1].xor(t);
					}

				}

				//Rho Pi
				t = state[1];
				for (int i = 0; i < 24; i++) {
					int j = keccakf_piln[i];
					bc[0] = state[j];
					state[j] = ROTL64(t, keccakf_rotc[i]);
					t = bc[0];
				}

				//Chi
				for (int j = 0; j < 25; j+=5) {
					for (int i = 0; i < 5; i++) bc[i] = state[j+i];
					for (int i = 0; i < 5; i++) 
						state[j+i] = state[j+1].xor(bc[(i+1)% 5].not()).and(bc[(i+2)%5]);
				}

				//Iota
				state[0] = state[0].xor(RC[r]);

			}
		}

		void sha3_init(int mdlen) {

			for (int i = 0; i < 25; i++)
				myState[i] = BigInteger.ZERO;

			this.mdlen = mdlen;
			rsiz = 200 - 2 * mdlen;
			pt = 0;
		}


		//Takes in some data that can be byte-indexed, and xors the data against the current state, 
		void sha3_update(byte[] data) {

			byte[] byteState = stateAsBytes(myState);

			//what is the pt for?
			int j = pt;
			for (int i = 0; i < data.length; i++) {

				//TODO: Byte-index an array of BigIntegers? 
				byteState[j++] ^= data[i];

				if (j >= rsiz) {
					myState = stateBigInts(byteState); //TODO: this introduces nulls:: fixed?
					keccakf(myState);
					j = 0;
				}
			}

			myState = stateBigInts(byteState);
			pt = j;

		}

		/**
		 * Converts the state array of BigIntegers to an array of bytes
		 * @param theState The state represented as an array of BigIntegers.
		 * 
		 * @return An array of bytes representing the state.
		 * 
		 */
		static byte[] stateAsBytes(BigInteger[] theState) {
			//is 200 the size of the sponge c or r?
			byte[] byteState = new byte[200];

			//Since there are 24 BigInts in the state
			for(int i = 0; i < 24; i++) {

				//Can't guarantee the BigInt is 8 bytes of data; check how many bytes of data BigInt is and then prepending padding to 8 bytes
				byte[] currBytes = new byte[8];
				byte[] bigIntBytes = theState[i].toByteArray();

				if (bigIntBytes.length < 8) {
					//adding padding
					int zeroPadCount = 8 - bigIntBytes.length;
					for (int index = 0; index < zeroPadCount; index++) {
						currBytes[index] = 0;
					}
					//adding message
					int bigIntBytesIndex = 0;
					for (int index = zeroPadCount; index < 8; index++) {
						currBytes[index] = bigIntBytes[bigIntBytesIndex++];
					}
				} else {
					currBytes = bigIntBytes;
				}

				//Since there are 8 bytes per BigInteger
				for (int j = 0; j < 8; j++) {
					byteState[8*i + j] = currBytes[j];
				}
			}

			return byteState;
		}

		/**
		 * Converts the state array of bytes to an array of BigIntegers.
		 * 
		 * @param theState The state represented as an array of bytes.
		 * @return A Biginteger array representation of the state.
		 */
		static BigInteger[] stateBigInts(byte[] theState) {

			BigInteger[] intState = new BigInteger[25];

			for (int i = 0; i < 200; i+=8) {
				byte[] currBytes = new byte[8];
				for (int j = 0; j < 8; j++) {
					currBytes[j] = theState[i+j];
				}
				//intState[i/25] = new BigInteger(currBytes); //???
				intState[i/8] = new BigInteger(currBytes);
			}

			return intState;
		}

		/**
		 * Does some shuffles, returns a digest known as md
		 * @return
		 */
		byte[] sha3_final() {

			byte[] md = new byte[mdlen];

			byte[] stateBytes = stateAsBytes(myState);

			stateBytes[pt] ^= 0x06;
			stateBytes[rsiz - 1] ^= 0x80;
			myState = stateBigInts(stateBytes);
			keccakf(myState);

			stateBytes = stateAsBytes(myState);
			myState = stateBigInts(stateBytes);

			for (int i = 0; i < mdlen; i++) {
				md[i] = stateBytes[i];
				//System.out.println();
			}



			return md;
		}

		//TODO: For init, update and final methods, do we rely on a return?
		//Or is this merely an artifact of C? Should they be void?

		/**
		 * Returns a hash from given data 
		 * @param 
		 */
		//Does this need a new, unique context...? Or can we hold onto our current one?
		//Keccak 
		byte[] sha3(byte[] in, int mdlen) {

			sha3_init(mdlen);
			sha3_update(in);
			return sha3_final();
		}

		void shake_xof() {

			byte[] byteState = stateAsBytes(myState);
			byteState[pt] ^= 0x04;
			byteState[rsiz-1] ^= 0x80;
			myState = stateBigInts(byteState);
			keccakf(myState);
			pt = 0;

		}

		void shake_out(byte[] out) {


			int j = pt;
			for (int i = 0; i < out.length; i++) {
				if (j >= rsiz) {
					keccakf(myState);
					j = 0;
				}
				byte[] stateBytes = stateAsBytes(myState);
				out[i] = stateBytes[j++];
			}
			pt = j;
		}

		/*k = data, 
		 * KMACXOF256(K, X, L, S):
Validity Conditions: len(K) <22040 and 0 â‰¤ L and len(S) < 22040
1. newX = bytepad(encode_string(K), 136) || X || right_encode(0).
2. T = bytepad(encode_string(â€œKMACâ€�) || encode_string(S), 136).
3. return KECCAK[512](T || newX || 00, L).

	KMACXOF256(String k, String x, ...
		 */

		public BigInteger ROTL64(BigInteger x, int y) {
			return x.shiftLeft(y).or(x.shiftRight(64 - y));

		}


		public String byte2String(byte toConvert) {
			String toReturn = "";

			byte byteMask = 0b0000001;

			for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
				int bit = byteMask & toConvert;
				if (bit == 0) toReturn = "0" + toReturn;
				else toReturn = "1" + toReturn;
				byteMask = (byte) (byteMask * 2);
			}

			return toReturn;
		}


	}
