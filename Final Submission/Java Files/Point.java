/*
 * Cryptography Pratical Project
 * Point.java by Maxfield England and Tyler Lorella
 * 
 * Implementation of E-521 elliptic curve for asymmetric cryptography. Contains constructors
 * and operations necessary to facilitate elliptic curve arithmetic as used in Main.java.
 */
import java.math.BigInteger;

//BigInteger Point class; particularly to facilitate points on the Edwards curve E521
public class Point {
	
	
	//2^521 - 1 : a mersenne prime, necessary for the curve.
	public static BigInteger mersenne = new BigInteger("2").pow(521).add(new BigInteger("-1"));

	//Edwards curve constant
	private static BigInteger d = new BigInteger("-376014");
	
	// 1/4 of the total values on E-521; a value utilized for digital signatures.
	public static BigInteger r = BigInteger.valueOf(2).pow(519).subtract(new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
	
	//Instance fields of the x and y coordinate values.
	private BigInteger x;
	private BigInteger y;
	
	public static Point G = new Point(BigInteger.valueOf(18), false);
	
	
	/**
	 * Constructs a point with a given x and y value.
	 * 
	 * @param x x-coordinate of point.
	 * @param y y-coordinate of point.
	 */
	Point(BigInteger x, BigInteger y) {
		this.x = x;
		this.y = y;
	}
	
	/**
	 * Creates the 'neutral point' (0, 1) when constructor called with no arguments.
	 */
	Point() {
		this.x = BigInteger.ZERO;
		this.y = BigInteger.ONE;
	}
	
	/**
	 * Returns the x value of the point.
	 * @return The point's x value.
	 */
	public BigInteger getX() {
		return x;
	}

	/**
	 * Returns the y value of the point.
	 * @return The point's y value.
	 */
	public BigInteger getY() {
		return y;
	}

	/**
	 * Creates point (x, y) based on full x coordinate and the least significant bit of y.
	 * @param x The x-coordinate of the point.
	 * @param ybit The least significant bit of y (true or false). NOTE: Represented as boolean?
	 */
	Point(BigInteger x, boolean ybit) {
		
		this.x = x;
		
		//intermediate values
		BigInteger int1 = BigInteger.ONE.subtract(x.modPow(BigInteger.valueOf(2), mersenne));
		BigInteger int2 = BigInteger.ONE.add(new BigInteger("376014").multiply(x.modPow(BigInteger.valueOf(2), mersenne)));
		BigInteger int3 = int1.multiply(int2.modInverse(mersenne));
		
		BigInteger root = sqrt(int3, mersenne, ybit);
		
		if (root != null) {
			this.y = root;
		}
		//if not acceptable, use the default? 
		else {
			this.y = BigInteger.ONE;
		}
		
	}
	
	/**
	 * Returns the sum of two points.
	 * 
	 * @param p1 The first point added.
	 * @param p2 The second point added.
	 * @return
	 */
	static Point pointSum(Point p1, Point p2) {
		
		
		BigInteger x1 = p1.x; 
		BigInteger x2 = p2.x;
		BigInteger y1 = p1.y;
		BigInteger y2 = p2.y;
		
		BigInteger denomdx = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
		
		BigInteger newxNum = (x1.multiply(y2)).add(y1.multiply(x2));
		BigInteger newx = (newxNum.multiply((BigInteger.ONE.add(denomdx)).modInverse(mersenne)));
		
		BigInteger newyNum = ((y1.multiply(y2)).subtract(x1.multiply(x2)));
		BigInteger newy = newyNum.multiply((BigInteger.ONE.subtract(denomdx).modInverse(mersenne)));
		
		newx = newx.mod(mersenne);
		newy = newy.mod(mersenne);
		
		return new Point(newx, newy);
	}
	
	/**
	 * Returns the sum that is the 'opposite' of the given point. 
	 * @return The opposite point.
	 */
	Point opposite() {
		
		BigInteger negX = x.modInverse(mersenne);
		return new Point(negX, y);
	}
	
	/**
	 * Returns the 'scalar multiple' of a point (a point added to itself s times) using
	 * double-and-add
	 * @param p The point to be multiplied.
	 * @param s The 'scalar' multiple of the point.
	 * @return A point on the curve that is effectively s * p.
	 */
	public static Point multiply(Point p, BigInteger s) {
		
		
		Point product = new Point();
		String bitString = s.toString(2);
		Point n = p;
		for (int i = bitString.length()-1; i >= 0; i--) {
			if (bitString.charAt(i) == '1'){
				product = Point.pointSum(product, n);
			}
			n = Point.pointSum(n, n);
		}
		return product;
		
	}
	
	/**
	 * Converts the current point object into a byte[] representation where the last byte is a 1
	 *  if the y value is odd, other y is even.
	 * @return a byte[] of length 67 (66-byte xval + 1-byte y)
	 */
	public byte[] toByte() {
		
		byte[] xBytes = x.toByteArray();
		int numZeroes = 66 - xBytes.length;
		byte ybit = 1;
		if (y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
			ybit = 0;
		}
		byte[] toReturn = new byte[67];

		int index = 0;
		for (; index < numZeroes; index++) {
			toReturn[index] = 0;
		}

		for (; index < 66; index++) {
			toReturn[index] = xBytes[index - numZeroes];
		}
		toReturn[66] = ybit;
		return toReturn;
	}
	
	/**
	 * Reads a byte array to console for legibility of its contents; useful for point data but 
	 * can be accessed elsewhere as a general utility method. 
	 * @param arr The byte array to be printed to the console.
	 */
	public static void readByteArray(byte[] arr) {
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		for (int i = 0; i < arr.length - 1; i++) sb.append(arr[i] + ", ");
		sb.append(arr[arr.length-1]);
		sb.append("]");
		System.out.println(sb.toString());
		
	}

	/**
	 * Compares this point to another object for point equivalence.
	 */
	@Override	
	public boolean equals(Object other) {
		
		if (other.getClass() != this.getClass()) return false;
		
		Point pointOther = (Point) other;
		
		return (x.equals(pointOther.x) && y.equals(pointOther.y));
		
	}
	
	/**
	 * credit: Paulo Barreto 
	 * 
	* Compute a square root of v mod p with a specified
	* least significant bit, if such a root exists.
	*
	* @param v the radicand.
	* @param p the modulus (must satisfy p mod 4 = 3).
	* @param lsb desired least significant bit (true: 1, false: 0).
	* @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
	* if such a root exists, otherwise null.
	*/
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
	 assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
	 if (v.signum() == 0) {
	 return BigInteger.ZERO;
	 }
	 BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
	 if (r.testBit(0) != lsb) {
	 r = p.subtract(r); // correct the lsb
	 }
	 return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}
	
}
