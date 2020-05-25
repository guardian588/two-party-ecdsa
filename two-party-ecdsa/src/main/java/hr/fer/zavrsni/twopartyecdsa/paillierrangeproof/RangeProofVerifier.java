package hr.fer.zavrsni.twopartyecdsa.paillierrangeproof;

import java.math.BigInteger;

import de.henku.jpaillier.PublicKey;
import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidRangeProofException;

public class RangeProofVerifier {

	public Comm comm;
	public BitSlice challenge;
	public Nonce nonce;
	public BigInteger q3;
	public int accuracy;
	public BigInteger c;
	public PublicKey ppk;
	private CiphertextPair[] ctxtPairs;

	public RangeProofVerifier(BigInteger q3, int accuracy) {
		challenge = BitSlice.randBitSlice(accuracy);
		
		nonce = new Nonce();
		comm = Comm.commit(challenge.get(), nonce);
		
		this.q3 = q3;
		this.accuracy = accuracy;
	}

	public void receiveCtxt(BigInteger c, PublicKey ppk, CiphertextPair[] ctxtPairs) {
		this.c = c;
		this.ppk = ppk;
		this.ctxtPairs = ctxtPairs;
		
	}

	public void verify(ProofPair[] proofPairs) throws InvalidRangeProofException {
		for (int i = 0; i < this.accuracy; i++) {
			ProofPair proofPair = proofPairs[i];
			this.verifyInstance(i, proofPair);
		}
	}
	
	private void verifyInstance(int i, ProofPair proofPair) throws InvalidRangeProofException {
		BigInteger lower = this.q3;
		BigInteger upper = this.q3.multiply(this.q3);
		
		CiphertextPair ctxtPair = this.ctxtPairs[i];
		
		byte ei = this.challenge.bit(i);
		
		if (ei == 0 && proofPair.j == 0) {
			if (proofPair.w1 == null || proofPair.r1 == null || proofPair.w2 == null || proofPair.r2 == null) {
				throw new InvalidRangeProofException();
			}
			
			boolean validW1Low = BigInteger.ZERO.compareTo(proofPair.w1) <= 0 && proofPair.w1.compareTo(lower) < 0;
			boolean validW1High = lower.compareTo(proofPair.w1) <= 0 && proofPair.w1.compareTo(upper) < 0;
			
			boolean validW2Low = BigInteger.ZERO.compareTo(proofPair.w2) <= 0 && proofPair.w2.compareTo(lower) < 0;
			boolean validW2High = lower.compareTo(proofPair.w2) <= 0 && proofPair.w2.compareTo(upper) < 0;
			
			boolean validW1 = validW1Low == !validW1High;
			boolean validW2 = validW2Low == !validW2High;
			
			BigInteger c1 = this.ppk.encrypt(proofPair.w1);
			BigInteger c2 = this.ppk.encrypt(proofPair.w2);
			
			boolean validC1 = c1.compareTo(ctxtPair.c1) == 0;
			boolean validC2 = c2.compareTo(ctxtPair.c2) == 0;
			
			if (!validW1 || !validW2 || !validC1 || !validC2) {
				throw new InvalidRangeProofException();
			}
		} else if (ei == 1 && proofPair.j == 1) {
			if (proofPair.w1 == null || proofPair.r1 == null || proofPair.w2 != null || proofPair.r2 != null) {
				throw new InvalidRangeProofException();
			}
			
			boolean validW1 = lower.compareTo(proofPair.w1) <= 0 && proofPair.w1.compareTo(this.ppk.getnSquared()) < 0;
			BigInteger cc1 = this.c.multiply(ctxtPair.c1);
			cc1 = cc1.mod(this.ppk.getnSquared());
			
			BigInteger cj = this.ppk.encrypt(proofPair.r1);
			
			boolean validCj = cc1.compareTo(cj) == 0;
			
			if (!validW1 || !validCj) {
				throw new InvalidRangeProofException();
			}
		} else if (ei == 1 && proofPair.j == 2) {
			if (proofPair.w1 != null || proofPair.r1 != null || proofPair.w2 == null || proofPair.r2 == null) {
				throw new InvalidRangeProofException();
			}
			
			boolean validW2 = lower.compareTo(proofPair.w2) <= 0 && proofPair.w2.compareTo(upper) < 0;
			
			BigInteger cc2 = this.c.multiply(ctxtPair.c2);
			cc2 = cc2.mod(this.ppk.getnSquared());
			
			BigInteger cj = this.ppk.encrypt(proofPair.w2);
			
			boolean validCj = cc2.compareTo(cj) == 0;
			
			if (!validW2 || !validCj) {
				throw new InvalidRangeProofException();
			}
		} else {
			throw new InvalidRangeProofException();
		}
	}

}
