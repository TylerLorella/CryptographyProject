import java.math.BigInteger;
import java.util.ArrayList;
	
public class Convulsions {
	
	//Questions: does using diversification string actually DO anything, or 
	//do these just feed additional random data that produce reliable, obfuscated results?
	byte[] KMACXOF256(byte[] K, byte[] X, int L, String S){
	
		byte[] x1 = bytepad(encode_string(K), BigInteger.valueOf(168));
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
		
		return cSHAKE256(newX, L, "KMAC", S);
	}
	
	byte[] cSHAKE256(byte[] X, int L, String N, String S){
		if (N.equals("") & S.equals("")) {
			return SHAKE256(X, L);
		}
		else {
			
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
			
			byte[] newX = new byte[x1.length + x2.length + X.length];
			int index = 0;
			for (byte b : x1) {
				newX[index] = x1[index];
				index++;
			}
			for (byte b : X) {
				newX[index] = X[index];
				index++;
			}
			for (byte b : x2) {
				newX[index] = x2[index];
				index++;
			}
			
			return Keccak(bytepad(newX, BigInteger.valueOf(L));
		}
	}
	
	byte[] SHAKE256(byte[] X, int L){ //Where do we feature inputs for keccak?
		return 
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
	public byte[] bytepad(byte[] X, BigInteger w) {

		byte[] z1 = left_encode(w);
		
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
		while ((tarLen + addZeroes) / 8 % w.intValue() != 0) {
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
}
