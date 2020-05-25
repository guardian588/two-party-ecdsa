package hr.fer.zavrsni.twopartyecdsa.paillierrangeproof;

import java.security.SecureRandom;

public class BitSlice {
	private byte[] vals;

	public BitSlice(byte[] vals) {
		this.vals = vals;
	}

	public byte[] get() {
		return vals;
	}
	
	public void set(byte[] vals) {
		this.vals = vals;
	}
	
	public byte bit(int i) {
		int byt = i / 8;
		int bit = i % 8;
		return (byte) ((vals[byt] >> (8 - bit)) & 0x01);
	}

	static BitSlice randBitSlice(int n) {
		int nbytes = (n + 7) / 8;
		byte[] b = new byte[nbytes];
		SecureRandom sr = new SecureRandom();
		sr.nextBytes(b);
		return new BitSlice(b);
	}
}
