import java.math.BigInteger;
import java.util.ArrayList;

public class Convulsions {

	KMACXOF256(BigInteger K, byte[] X, int L, String S){

		newX = bytepad(encode_string(K), 168) || X || right_encode(0);
		return cSHAKE256(newX, L, "KMAC", S);
	}

	cSHAKE256(String X, int L, String N, String S){
		if (N.equals("") & S.equals("")) {
			return SHAKE256(X, L);
		}
		else {
			return
		}
	}

	SHAKE256(String X, int L){ //Where do we feature inputs for keccak?
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
}
