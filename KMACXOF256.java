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

	int[] keccakf_piln = {10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
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

		//Initialize round constants
		for (int i = 0; i < 24; i++) {
			RC[i] = new BigInteger(toRC[i], 16);

			//System.out.println("Number: " + RC[i]);
		}

		sha3_init(mdlen);
		//sha3_update(m.getBytes());
		sha3_update(m);

	}

	public String getData() {
		byte[] messageDigest = sha3_final();
		//return sha3_final();
		String toReturn = "";
		//for (byte element: messageDigest) toReturn = toReturn + " " + Integer.toBinaryString(element);
		//for (byte element: messageDigest) System.out.println( element );
		
		for (int index = 0; index < messageDigest.length; index++) {
			toReturn = toReturn + "byte " + index + ", byte String: " + Integer.toBinaryString(index) + 
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


	//Prepends an encoding of the integer w to the string x, and pads the result
	//with zeros until it is a byte string whose length in bytes is a multiple
	//of w
	//used for encoded strings
	public String bytepad(String x, int w) {

		String z = left_encode(w);
		while (z.length() % 8 != 0) {

			z = z + "0";
		}
		while ((z.length() / 8.0) % w != 0) {

			z = z + "00000000";

		}

		return z;

	}

	//if s.length() < 2^2040,
	//Returns the left_encode of the string's length concatenated w the string
	public String encode_string(String s) {

		return left_encode(s.length()) + s;
	}

	//Encode from the beginning of the string by inserting the
	//length of the byte string before the byte string representation of x
	/*
	 * Cond:
	 * n is smallest positive int for which 2^8n > x
	 * x = sum(2^8(n-i)*x_i for i = {1, n}
	 * O_i = enc_8(x_i), for i = {1, n}
	 * O_(n+1) = enc_8(n)
	 */
	public String left_encode(int x) {


		return null;

	}

	public String right_encode(int x){

		return null;
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

}
