package hr.fer.zavrsni.twopartyecdsa.paillierrangeproof;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.concurrent.Semaphore;

import de.henku.jpaillier.KeyPair;
import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidProofPairException;

public class RangeProofProver {

	public CiphertextPair[] ctxtPairs;
	public BigInteger x;
	public BigInteger r;
	public KeyPair psk;
	public BigInteger q;
	public BigInteger q3;
	public Comm challengeComm;
	public int accuracy;
	public SecretPair[] secPairs;

	public RangeProofProver(BigInteger x1, BigInteger q, BigInteger q3, KeyPair psk, Comm rpChalComm,
			int rangeSecBits) {
		// TODO Auto-generated constructor stub
	}
	
	public RangeProofProver(BigInteger x, BigInteger r, BigInteger q, BigInteger q3, KeyPair psk, Comm comm, int accuracy) {
		secPairs = SecretPair.newSecretPairs(accuracy);
		ctxtPairs = CiphertextPair.newCiphertextPairs(accuracy);
		
		BitSlice flipBits = randBitSlice(accuracy);
		
		this.x = x;
		this.r = r;
		this.q = q;
		this.q3 = q3;
		this.psk = psk;
		this.challengeComm = comm;
		this.accuracy = accuracy;
				
		for (int i = 0; i < this.accuracy; i++) {
			byte flipi = flipBits.bit(i);
			this.initInstance(i, flipi);
		}
	}
	
	private void initInstance(int i, byte flipi) {
		SecureRandom sr = new SecureRandom();
		byte[] w1b = new byte[this.q3.toByteArray().length];
		BigInteger w1;
		do {
			sr.nextBytes(w1b);
			w1 = new BigInteger(w1b);
		} while (w1.compareTo(this.q3) >= 0);
		w1 = w1.add(this.q3);
		
		BigInteger w2 = w1.subtract(this.q3);
		
		byte[] r1b = new byte[this.psk.getPublicKey().getN().toByteArray().length];
		BigInteger r1;
		do {
			sr.nextBytes(r1b);
			r1 = new BigInteger(r1b);
		} while (r1.compareTo(this.psk.getPublicKey().getN()) >= 0);
		
		byte[] r2b = new byte[this.psk.getPublicKey().getN().toByteArray().length];
		BigInteger r2;
		do {
			sr.nextBytes(r2b);
			r2 = new BigInteger(r2b);
		} while (r2.compareTo(this.psk.getPublicKey().getN()) >= 0);
		
		switch (flipi) {
		case 0:
			this.secPairs[i] = new SecretPair(w1, r1, w2, r2);
			break;
		case 1:
			this.secPairs[i] = new SecretPair(w2, r2, w1, r1);
		}
		
		BigInteger c1 = this.psk.getPublicKey().encrypt(this.secPairs[i].w1);
		BigInteger c2 = this.psk.getPublicKey().encrypt(this.secPairs[i].w2);
		
		this.ctxtPairs[i] = new CiphertextPair(c1, c2);
	}

	public ProofPair[] prove(BitSlice challenge, Nonce nonce) throws InvalidProofPairException {
		this.challengeComm.verify(challenge.get(), nonce);
		ProofPair[] proofPairs = ProofPair.newProofPairs(this.accuracy);
		
		for (int i = 0; i < this.accuracy; i++) {
			byte ei = challenge.bit(i);
			this.proveInstance(i, ei, proofPairs);
		}
		
		return proofPairs;
	}
	
	private void proveInstance(int i, byte ei, ProofPair[] proofPairs) throws InvalidProofPairException {
		BigInteger lower = this.q3;
		BigInteger upper = this.q3.add(this.q3);
		
		switch (ei) {
		case 0:
			proofPairs[i] = new ProofPair((byte) 0, this.secPairs[i].w1, this.secPairs[i].r1, this.secPairs[i].w2, this.secPairs[i].r2);
			break;
		case 1:
			BigInteger w1x = this.secPairs[i].w1.add(this.x);
			BigInteger w2x = this.secPairs[i].w2.add(this.x);
			boolean use1 = lower.compareTo(w1x) <= 0 && w1x.compareTo(upper) < 0;
			boolean use2 = lower.compareTo(w2x) <= 0 && w2x.compareTo(upper) < 0;
			
			if (use1 && use2) {
				throw new InvalidProofPairException();
			} else if (use1) {
				BigInteger r = this.r.multiply(this.secPairs[i].r1);
				r = r.mod(this.psk.getPublicKey().getN());
				
				proofPairs[i] = new ProofPair();
				proofPairs[i].j = 1;
				proofPairs[i].w1 = w1x;
				proofPairs[i].r1 = r;
			} else if (use2) {
				BigInteger r = this.r.multiply(this.secPairs[i].r2);
				r = r.mod(this.psk.getPublicKey().getN());
				
				proofPairs[i] = new ProofPair();
				proofPairs[i].j = 2;
				proofPairs[i].w2 = w2x;
				proofPairs[i].r2 = r;
			} else {
				throw new InvalidProofPairException();
			}
		}
	}

}
