package hr.fer.zavrsni.twopartyecdsa.exceptions;

public abstract class TwoPartyECDSAException extends Exception {
	/**
	 * 
	 */
	private static final long serialVersionUID = 337160718762021808L;
	
	protected static String defaultMessage;
	
	public TwoPartyECDSAException() {
		super(defaultMessage);
	}
	
	public TwoPartyECDSAException(String errorMessage) {
		super(errorMessage);
	}
	
	public TwoPartyECDSAException(String errorMessage, Throwable error) {
		super(errorMessage, error);
	}

}
