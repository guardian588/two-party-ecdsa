package hr.fer.zavrsni.twopartyecdsa.sign;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;
import org.bouncycastle.math.ec.ECAlgorithms;

import hr.fer.zavrsni.twopartyecdsa.ECOperations;
import hr.fer.zavrsni.twopartyecdsa.Party1PrivateKey;
import hr.fer.zavrsni.twopartyecdsa.TwoPartyECDSA;
import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;

public class Party1SignCtx {
	public Party1SignCtx(byte[] msg, Party1PrivateKey sk) {
		this.msg = msg;
		this.sk = sk;
	}

	private byte[] msg;
	private Party1PrivateKey sk;
	
	private PrivateKey k1;
	public PublicKey r1;
	public DiscreteLogProofOfKnowledge r1PoK;
	public Nonce r1PoKNonce;
	
	public PublicKey r2;
	
	public void zero() {
		try {
			this.k1.destroy();
		} catch (DestroyFailedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public SignMsg1 signMsgPhase1(long sid) {
		PrivateKey k1 = TwoPartyECDSA.newPrivKey().getPrivate();
		
		DiscreteLogProofOfKnowledge r1PoK = new DiscreteLogProofOfKnowledge(TwoPartyECDSA.getSign1Msg(), k1);
		
		Nonce r1Nonce = new Nonce();
		Comm r1Comm = Comm.commit(r1PoK.bytes(), r1Nonce);
		
		this.k1 = k1;
		this.r1 = ECOperations.getPublicKeyFromPrivate(k1);
		this.r1PoK = r1PoK;
		this.r1PoKNonce = r1Nonce;
		
		return new SignMsg1(r1Comm);
	}
	
	public SignMsg3 signMsgPhase3(long sid, SignMsg2 m2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		m2.r2PoK.verify(TwoPartyECDSA.getSign2Msg());
		
		PublicKey r2 = ECOperations.getDecodedPublicKey(m2.r2PoK.pk);
		
		this.r2 = r2;
		
		return new SignMsg3(this.r1PoK, this.r1PoKNonce);
	}
	
	public Signature signMsgPhase5(long sid, SignMsg4 m4) {
		BigInteger s1 = this.sk.psk.decrypt(m4.getC3());
		
		BigInteger k1Inv = new BigInteger(this.k1.getEncoded());
		k1Inv = k1Inv.modInverse(this.sk.getCfg().q);
		
		BigInteger s2 = k1Inv.multiply(s1);
		s2 = s2.mod(this.sk.getCfg().q);
		
		BigInteger qMinusS = this.sk.getCfg().q.subtract(s2);
		
		BigInteger s;
		if (s2.compareTo(qMinusS) <= 0) {
			s = s2;
		} else {
			s = qMinusS;
		}
		
		ECPoint r2P = ((ECPublicKey) this.r2).getW();
		ECPoint rx = ECOperations.scalarMultiplication(r2P, this.k1.getEncoded());
		BigInteger r = rx.getAffineX().mod(this.sk.getCfg().q);
		
		
		Signature sig = new Signature(r, s);
		
		// sig.verify()
		
		return sig;
		
	}
}
