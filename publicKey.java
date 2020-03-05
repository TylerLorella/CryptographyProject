
//Extra credit: write key to file
	private Point getKey(byte[] pw) {

		byte[] secretBytes = (new KMACXOF256(pw, "".getBytes(), 512, "K").getData());

		BigInteger s = new BigInteger(secretBytes);
		s = s.multiply(BigInteger.valueOf(4));

		BigInteger newX = Point.G.getX().multiply(s);
		BigInteger newY = Point.G.getY().multiply(s);

		Point V = new Point(newX, newY);

		return V;
	}

	private static void pubEncrypt(Point V, byte[] m) {

		SecureRandom secureRandom = new SecureRandom();
		byte[] randomVals = new byte[64];
		secureRandom.nextBytes(randomVals);

		BigInteger k = new BigInteger(randomVals);
		k = k.multiply(BigInteger.valueOf(4));

		BigInteger newX =  k.multiply(V.getX());
		BigInteger newY = k.multiply(V.getY());

		Point W = new Point(newX, newY);

		BigInteger zX = k.multiply(Point.G.getX());
		BigInteger zY = k.multiply(Point.G.getY());

		Point Z = new Point(zX, zY);

		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), m.length, "PKE").getData();
		byte[] c = xorBytes(m, mask);
		byte[] t = new KMACXOF256(ka, m, 512, "PKA").getData();

		//TODO: Put (Z, c, t) to file
		
	}

	//(Z, c, t) as a whole, or each of {Z, c, t}?
	private static byte[] pubDecrypt(byte[] pw, Point Z, byte[] c, byte[] t) {
		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s = s.multiply(BigInteger.valueOf(4));

		BigInteger wX = s.multiply(Z.getX());
		BigInteger wY = s.multiply(Z.getY());

		Point W = new Point(wX, wY);

		byte[] keka = (new KMACXOF256(W.getX().toByteArray(), ("").getBytes(), 1024, "P")).getData(); 
		byte[] ke = new byte[keka.length/2];
		byte[] ka = new byte[keka.length/2];
		for (int index = 0; index < keka.length/2; index++) {
			ke[index] = keka[index];
		}
		for (int index = keka.length/2; index < keka.length; index++) {
			ka[index - keka.length/2] = keka[index]; 
		}

		byte[] mask = new KMACXOF256(ke, "".getBytes(), c.length, "PKE").getData();
		byte[] m = xorBytes(c, mask);
		byte[] t2 = new KMACXOF256(ka, m, 512, "PKA").getData();

		//if t = t2, return c; otherwise the message is not valid :(
		boolean equiv = true;
		if (t.length != t2.length) equiv = false;
		for (int i = 0; i < t.length; i++) {
			if (t[i] != t2[i]) equiv = false;
		}
		
		if (equiv) {
			return m;
		}
		else {
			return "Invalid message".getBytes();
		}
	}
	
	private byte[] signatureGen(byte[] m, byte[] pw){
		
		BigInteger s = new BigInteger(new KMACXOF256(pw, "".getBytes(), 512, "K").getData());
		s.multiply(BigInteger.valueOf(4));
		
		BigInteger k = new BigInteger(new KMACXOF256(s.toByteArray(), m, 512, "N").getData());
		k.multiply(BigInteger.valueOf(4));
		
		BigInteger uX = k.multiply(Point.G.getX());
		
		BigInteger h = new BigInteger(new KMACXOF256(uX.toByteArray(), m, 512, "T").getData());
		BigInteger z = k.subtract(h.multiply(s)).mod(Point.r);
		
		return (concatinateBytes(h.toByteArray(), z.toByteArray()));
		
	}
	
	private boolean signatureVerify(byte[] hz, byte[] m, Point V) {
		
		byte[] h = new byte[512];
		byte[] z = new byte[hz.length -512];
		for (int i = 0; i < h.length; i++) {
			h[i] = hz[i];
		}
		for (int i = 0; i < z.length; i++) {
			z[i] = hz[512+i];
		}

		BigInteger hVal = new BigInteger(h);
		BigInteger zVal = new BigInteger(z);
		
		BigInteger uX = zVal.multiply(Point.G.getX()).add(hVal.multiply(V.getX()));
		byte[] test = new KMACXOF256(uX.toByteArray(), m, 512, "T").getData();
		
		boolean ret = true;
		if (test.length != h.length) ret = false;
		for (int i = 0; i < h.length; i++) {
			if (h[i] != test[i]) ret = false;
		}
		
		return ret;
	}
