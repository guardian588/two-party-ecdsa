package hr.fer.zavrsni.twopartyecdsa.sign;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.DestroyFailedException;

import hr.fer.zavrsni.twopartyecdsa.ECOperations;
import hr.fer.zavrsni.twopartyecdsa.Party2PrivateKey;
import hr.fer.zavrsni.twopartyecdsa.TwoPartyECDSA;
import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;

public class Party2SignCtx {
	public Party2SignCtx(byte[] msg, Party2PrivateKey sk) {
		this.msg = msg;
		this.sk = sk;
	}

	private byte[] msg;
	private Party2PrivateKey sk;
	
	public Comm r1PoKComm;
	private PrivateKey k2;
	public PublicKey r2;
	public DiscreteLogProofOfKnowledge r2PoK;
	
	public PublicKey r1;
	
	public void zero() {
		try {
			this.k2.destroy();
		} catch (DestroyFailedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public SignMsg2 signMsgPhase2(long sid, SignMsg1 m1) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		PrivateKey k2 = TwoPartyECDSA.newPrivKey().getPrivate();
		
		DiscreteLogProofOfKnowledge r2PoK = new DiscreteLogProofOfKnowledge(TwoPartyECDSA.getSign2Msg(), this.k2);
		
		this.r1PoKComm = m1.r1PoKComm;
		this.k2 = k2;
		this.r2 = ECOperations.getPublicKeyFromPrivate(k2);
		this.r2PoK = r2PoK;
		
		return new SignMsg2(r2PoK);
	}
	
	public SignMsg4 signMsgPhase4(long sid, SignMsg3 m3) throws InvalidKeySpecException, NoSuchAlgorithmException {
		BigInteger m = new BigInteger(this.msg);
		
		byte[] rhoB = new byte[this.sk.getCfg().qSquared.toByteArray().length];
		SecureRandom sr = new SecureRandom();
		BigInteger rho;
		do {
			sr.nextBytes(rhoB);
			rho = new BigInteger(rhoB);
		} while (rho.compareTo(this.sk.getCfg().qSquared) > 0);
		
		BigInteger rhoq = rho.multiply(this.sk.getCfg().q);
		rhoq = rhoq.mod(this.sk.getCfg().qSquared);
		
		BigInteger k2Inv = new BigInteger(this.k2.getEncoded());
		k2Inv = k2Inv.modInverse(this.sk.getCfg().q);
		
		BigInteger pt = k2Inv.multiply(m);
		pt = pt.mod(this.sk.getCfg().q);
		pt = pt.add(rhoq);
		
		BigInteger c1 = this.sk.ppk.encrypt(pt);
		
		this.r1PoKComm.verify(m3.r1PoK.bytes(), m3.r1PoKNonce);
		
		m3.r1PoK.verify(TwoPartyECDSA.getSign1Msg());
		
		PublicKey r1 = ECOperations.getDecodedPublicKey(m3.r1PoK.pk);
		
		ECPoint r1Point = ((ECPublicKey) r1).getW();
		ECPoint rx = ECOperations.scalarMultiplication(r1Point, this.k2.getEncoded());
		
		BigInteger r = rx.getAffineX().mod(this.sk.getCfg().q);
		
		BigInteger x2Int = new BigInteger(this.sk.x2sk.getEncoded());
		
		BigInteger v = k2Inv.multiply(r);
		v = v.multiply(x2Int);
		v = v.mod(this.sk.getCfg().q);
		
		BigInteger c2 = this.sk.cKey.modPow(v, this.sk.ppk.getnSquared());
		
		BigInteger c3 = c1.multiply(c2);
		c3 = c3.mod(this.sk.ppk.getnSquared());
		
		this.r1 = r1;
		
		return new SignMsg4(c3);
	}
}
