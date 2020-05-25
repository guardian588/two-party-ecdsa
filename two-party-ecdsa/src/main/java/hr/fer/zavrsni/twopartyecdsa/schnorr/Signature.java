package hr.fer.zavrsni.twopartyecdsa.schnorr;

public class Signature {
	private byte[] signature = new byte[Schnorr.SIGNATURESIZE];
	
	public byte[] getSignature() {
		return signature;
	}
	
	public void setSignature(byte[] signature) {
		if (signature.length == Schnorr.SIGNATURESIZE) {
			this.signature = signature;
		} else {
			throw new IllegalArgumentException("Invalid sized signature");
		}
	}
	
}
