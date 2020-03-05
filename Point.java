import java.math.BigInteger;

//BigInteger Point class; particularly to facilitate points on the Edwards curve E521
public class Point {
	
	
	//2^521 - 1 : a mersenne prime, necessary for the curve.
	private BigInteger mersenne = new BigInteger("2").pow(521).add(new BigInteger("-1"));

	//Edwards curve constant
	private BigInteger d = new BigInteger("-376014");

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
	
	public BigInteger getX() {
		return x;
	}

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
		BigInteger int1 = BigInteger.ONE.subtract(x.modPow(BigInteger.TWO, mersenne));
		BigInteger int2 = BigInteger.ONE.add(new BigInteger("376014").multiply(x.modPow(BigInteger.TWO, mersenne)));
		BigInteger int3 = int1.multiply(int2.modInverse(mersenne));
		
		BigInteger root = sqrt(int3, mersenne, ybit);
		
		if (!root.equals(null)) {
			this.y = root;
		}
		//if not acceptable, use the default? TODO
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
	Point pointSum(Point p1, Point p2) {
		
		BigInteger x1 = p1.x; 
		BigInteger x2 = p2.x;
		BigInteger y1 = p1.y;
		BigInteger y2 = p2.y;
		
		BigInteger denomdx = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);
		
		BigInteger newxNum = (x1.multiply(y2)).add(y1.multiply(x2));
		BigInteger newx = (newxNum.multiply((BigInteger.ONE.add(denomdx)).modInverse(mersenne)));
		
		BigInteger newyNum = ((y1.multiply(y2)).subtract(x1.multiply(x2)));
		BigInteger newy = newyNum.multiply((BigInteger.ONE.subtract(denomdx).modInverse(mersenne)));
		
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
