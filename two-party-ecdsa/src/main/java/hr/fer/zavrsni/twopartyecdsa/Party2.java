package hr.fer.zavrsni.twopartyecdsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;

import hr.fer.zavrsni.twopartyecdsa.commit.Comm;
import hr.fer.zavrsni.twopartyecdsa.commit.Nonce;
import hr.fer.zavrsni.twopartyecdsa.discretelogpok.DiscreteLogProofOfKnowledge;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidPrimalityProofException;
import hr.fer.zavrsni.twopartyecdsa.exceptions.InvalidRangeProofException;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg1;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg2;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg3;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg4;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg5;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg6;
import hr.fer.zavrsni.twopartyecdsa.keygen.KeyGenMsg7;
import hr.fer.zavrsni.twopartyecdsa.paillierrangeproof.RangeProofVerifier;

//import de.henku.jpaillier.KeyPair;

public class Party2 {
	private Config cfg;
	
	public Comm x1PoKComm;
	private java.security.KeyPair x2;
//	public PublicKey X2;
	public DiscreteLogProofOfKnowledge x2PoK;
	public RangeProofVerifier rpVerifier;
	
	public PublicKey x1;
	public de.henku.jpaillier.PublicKey ppk;
	public BigInteger cKey;
	public BigInteger cPrime;
	public BigInteger a;
	public BigInteger b;
	public Nonce abNonce;
	
	public Comm alphaComm;
	
	public PublicKey q;
	
	public Party2(Config cfg) {
		this.cfg = cfg;
	}
	
	public java.security.KeyPair getX2() {
		return x2;
	}

	public void setX2(java.security.KeyPair x2) {
		this.x2 = x2;
	}
	
	public KeyGenMsg2 keyGenPhase2(long sid, KeyGenMsg1 m1) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		java.security.KeyPair x2;
		if (this.x2 != null) {
			x2 = this.x2;
		} else {
			x2 = TwoPartyECDSA.newPrivKey();
		}
		
		DiscreteLogProofOfKnowledge x2PoK = new DiscreteLogProofOfKnowledge(TwoPartyECDSA.getKeyGen2Msg(), x2);
		
		RangeProofVerifier rpVerifier = new RangeProofVerifier(this.cfg.q3, this.cfg.rangeSecBits);
		
		this.x1PoKComm = m1.x1PoKComm;
		this.x2 = x2;
		this.x2PoK = x2PoK;
		this.rpVerifier = rpVerifier;
		
		return new KeyGenMsg2(x2PoK, this.rpVerifier.comm);
	}

	public KeyGenMsg4 keyGenPhase4(long sid, KeyGenMsg3 m3) throws InvalidKeySpecException, NoSuchAlgorithmException, InvalidPrimalityProofException {
		this.x1PoKComm.verify(m3.x1PoK.bytes(), m3.x1PoKNonce);
		m3.x1PoK.verify(TwoPartyECDSA.getKeyGen1Msg());
		m3.pProof.verify();
		
		PublicKey x1 = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(m3.x1PoK.pk));
		BigInteger cKey = new BigInteger(m3.getcKey());
		BigInteger c = new BigInteger(cKey.toByteArray());
		
		this.rpVerifier.receiveCtxt(c, m3.pProof.pk, m3.rpctxtPairs);
		SecureRandom secureRandom = new SecureRandom();
		int a = secureRandom.nextInt(this.cfg.q.intValue());
		int b = secureRandom.nextInt(this.cfg.qSquared.intValue());
		
		BigInteger cPrime = new BigInteger(c.toByteArray());
		cPrime = cPrime.modPow(BigInteger.valueOf(a), m3.pProof.pk.getnSquared());
		
		BigInteger tmp = m3.pProof.pk.getG().modPow(BigInteger.valueOf(b), m3.pProof.pk.getnSquared());
		
		cPrime = cPrime.multiply(tmp);
		cPrime = cPrime.mod(m3.pProof.pk.getnSquared());
		
		byte[] data = ByteBuffer.allocate(8).putInt(a).putInt(b).array();
		
		Nonce abNonce = new Nonce();
		Comm abComm = Comm.commit(data, abNonce);
		
		this.x1 = x1;
		this.ppk = m3.pProof.pk;
		this.cKey = cKey;
		
		this.cPrime = cPrime;
		this.a = BigInteger.valueOf(a);
		this.b = BigInteger.valueOf(b);
		this.abNonce = abNonce;
		
		return new KeyGenMsg4(this.rpVerifier.challenge.get(), this.rpVerifier.nonce, cPrime, abComm);
	}
	
	public KeyGenMsg6 KeyGenPhase6(long sid, KeyGenMsg5 m5) throws InvalidRangeProofException {
		this.rpVerifier.verify(m5.rpProofPairs);
		
		this.alphaComm = m5.alphaComm;
		return new KeyGenMsg6(this.a, this.b, this.abNonce);
	}
	
	public void KeyGenPhase8(long sid, KeyGenMsg7 m7) throws NoSuchAlgorithmException, InvalidKeySpecException {
		this.alphaComm.verify(m7.alphaPK.toByteArray(), m7.alphaNonce);
		
		ECPoint x1 = ((ECPublicKey) this.x1).getW();
		ECPoint aQ = ECOperations.scalarMultiplication(x1, this.a.toByteArray());
		ECPoint b = ECOperations.scalarBaseMultiplication(this.b.toByteArray());
		ECPoint qq = ECOperations.addPoint(aQ, b);
		
		ECNamedCurveParameterSpec specs = ECNamedCurveTable.getParameterSpec("scep256k1");
		KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
		ECNamedCurveSpec params = new ECNamedCurveSpec("scep265k1", specs.getCurve(), specs.getG(), specs.getN());
		ECPublicKeySpec qqPubKeySpec = new ECPublicKeySpec(qq, params);
		PublicKey qqPk = kf.generatePublic(qqPubKeySpec);
		byte[] qqc = qqPk.getEncoded();
		
		if (!m7.alphaPK.equals(new BigInteger(qqc))) {
			// TODO
			throw new Exception();
		}
		
		ECPoint q = ECOperations.scalarMultiplication(x1, this.x2.getPrivate().getEncoded());
		ECPublicKeySpec qPubKeySpec = new ECPublicKeySpec(q, params);
		PublicKey qPk = kf.generatePublic(qPubKeySpec);
		
		this.q = qPk;
	}
	
	public Party2PrivateKey privateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
		if (this.ppk == null || this.cKey == null || this.x2 == null || this.q == null) {
			throw new Exception();
		}
		
		byte[] qcpk = this.q.getEncoded();
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("scep256k1");
	    KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
	    ECNamedCurveSpec params = new ECNamedCurveSpec("scep256k1", spec.getCurve(), spec.getG(), spec.getN());
	    ECPoint point =  ECPointUtil.decodePoint(params.getCurve(), qcpk);
	    ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
	    ECPublicKey q = (ECPublicKey) kf.generatePublic(pubKeySpec);
	    return new Party2PrivateKey(this.cfg, this.ppk, this.cKey, this.x2.getPrivate(), q);
	}
}
