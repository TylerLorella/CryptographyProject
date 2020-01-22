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
	
	BigInteger[] myState = new BigInteger[25];
	
	//State instance fields
	private int mdlen;
	private int rsiz;
	
	//Keeps track of which bytes have already been operated on in between update steps
	private int pt;
	

	/**
	 * 
	 * @param k Key
	 * @param m Authenticated data
	 * @param L output bit length
	 * @param S diversification string
	 */
	public KMACXOF256(final BigInteger k, final String m, final int L, final String S) {

		//Initialize round constants
		for (int i = 0; i < 24; i++) {

			RC[i] = new BigInteger(toRC[i], 16);

			System.out.println("Number: " + RC[i]);
		}


	}
	
	//return? where is state changed
	public void keccakf(BigInteger[] state) {
		
		//For 24 rounds 
		for (int r = 0 ; r < 24; r++) {
			
			//Theta function
			for (int i = 0; i < 5; i++) {
				
				bc[i] = state[i].xor(state[i+5]).xor(state[i+10]).xor(state[i+15]).xor(state[i+20]);
			}
			
			for (int i = 0; i < 5; i++) {
				
				//Fs in chat
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
	
	int sha3_init(int mdlen) {
		
		for (int i = 0; i < 25; i++)
			myState[i] = BigInteger.ZERO;
		
		this.mdlen = mdlen;
		rsiz = 200 - 2 * mdlen;
		pt = 0;
		
		return 1;
	}
	
	
	//Takes in some data that can be byte-indexed, and xors the data against the current state, 
	int sha3_update(byte[] data) {
		
		int j = pt;
		for (int i = 0; i < data.length; i++) {
			
			//TODO: Byte-index an array of BigIntegers? 
			
			if (j >= rsiz) {
				keccakf(myState);
				j = 0;
			}
		}
		
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


	/*
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
	
	
	public static void main(String args[]) {

		KMACXOF256 myKmac = new KMACXOF256(BigInteger.ZERO, "", 1, "");


	}

}
