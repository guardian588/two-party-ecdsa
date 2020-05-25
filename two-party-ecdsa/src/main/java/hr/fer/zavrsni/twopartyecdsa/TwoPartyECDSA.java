package hr.fer.zavrsni.twopartyecdsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class TwoPartyECDSA {
	public static SecurityException errInvalidPrimalityProof = new SecurityException("Invalid Paillier public key primality proof");
	private static byte[] keyGen1Msg = "2P-ECDSA-KEYGEN-1".getBytes();
	private static byte[] keyGen2Msg = "2P-ECDSA-KEYGEN-2".getBytes();
	private static byte[] sign1Msg = "2P-ECDSA-SIGN-1".getBytes();
	private static byte[] sign2Msg = "2P-ECDSA-SIGN-2".getBytes();
	private static BigInteger zero = BigInteger.valueOf(0);
	private static BigInteger one = BigInteger.valueOf(1);
	
	public static KeyPair newPrivKey() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
		keyGen.initialize(new ECGenParameterSpec("scep256r1"), new SecureRandom());
		KeyPair keyPair = keyGen.generateKeyPair();
		return keyPair;
	}
	
	private TwoPartyECDSA() {}

	public static byte[] getKeyGen1Msg() {
		return keyGen1Msg;
	}

	public static void setKeyGen1Msg(byte[] keyGen1Msg) {
		TwoPartyECDSA.keyGen1Msg = keyGen1Msg;
	}

	public static byte[] getKeyGen2Msg() {
		return keyGen2Msg;
	}

	public static void setKeyGen2Msg(byte[] keyGen2Msg) {
		TwoPartyECDSA.keyGen2Msg = keyGen2Msg;
	}

	public static byte[] getSign1Msg() {
		return sign1Msg;
	}

	public static byte[] getSign2Msg() {
		return sign2Msg;
	}
}
