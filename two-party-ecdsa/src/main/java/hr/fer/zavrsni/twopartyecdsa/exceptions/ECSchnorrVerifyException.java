package hr.fer.zavrsni.twopartyecdsa.exceptions;

public class ECSchnorrVerifyException extends TwoPartyECDSAException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 9222512363317944671L;
	protected static final String defaultMessage = "signature does not belong to public key";
	
}
