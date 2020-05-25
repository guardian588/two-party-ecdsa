package hr.fer.zavrsni.twopartyecdsa.schnorr;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import hf.fer.zavrsni.twopartyecdsa.exceptions.ECSchnorrVerifyException;
import hr.fer.zavrsni.twopartyecdsa.ECOperations;

public class Schnorr {
	public static final int SIGNATURESIZE = 64;
	
	public static Signature sign(PrivateKey sk, byte[] hash) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
		keyGen.initialize(new ECGenParameterSpec("scep256k1"), new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(hash);
		md.update(keyPair.getPublic().getEncoded());
		byte[] e = md.digest();
		
		BigInteger kInt = new BigInteger(keyPair.getPrivate().getEncoded());
		BigInteger eInt = new BigInteger(e);
		BigInteger rInt = new BigInteger(sk.getEncoded());
		
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("scep256k1");
		
		BigInteger s = eInt.multiply(rInt);
		s = kInt.subtract(s);
		s = s.mod(spec.getN());
		
		Signature sig = new Signature();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(e);
		baos.write(s.toByteArray(), e.length, SIGNATURESIZE/2);
		sig.setSignature(baos.toByteArray());
		
		keyGen = null;
		
		return sig;
	}

	public static void verify(Signature sig, PublicKey pk, byte[] hash) throws NoSuchAlgorithmException, InvalidKeySpecException {
		ECPoint pkp = ((ECPublicKey) pk).getW();
		
		ECPoint sG = ECOperations.scalarBaseMultiplication(Arrays.copyOfRange(sig.getSignature(), SIGNATURESIZE/2, SIGNATURESIZE));
		ECPoint ePK = ECOperations.scalarMultiplication(pkp, Arrays.copyOfRange(sig.getSignature(), 0, SIGNATURESIZE/2));
		ECPoint kG = ECOperations.addPoint(sG, ePK);
		PublicKey kGPK = ECOperations.getPublicKeyFromPoint(kG);
		
		MessageDigest md = MessageDigest.getInstance("SHA256");
		md.update(hash);
		byte[] e = md.digest(kGPK.getEncoded());
		
		for (int i = 0; i < e.length; i++) {
			if (sig.getSignature()[i] != e[i]) {
				throw new ECSchnorrVerifyException()
			}
		}
	}

}
