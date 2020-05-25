package hr.fer.zavrsni.twopartyecdsa.commit;

import java.math.BigInteger;

public class Nonce {
	private BigInteger val;
	
	public Nonce(byte[] val) {
		this.val = new BigInteger(val);
	}
	
	public Nonce(BigInteger val) {
		this.val = val;
	}
	
	public Nonce() {
		val = BigInteger.ZERO;
	}
	
	public BigInteger getVal() {
		return val;
	}
	
	public void setVal(BigInteger val) {
		this.val = val;
	}
	
	public void setVal(byte[] val) {
		this.val = new BigInteger(val);
	}
}
