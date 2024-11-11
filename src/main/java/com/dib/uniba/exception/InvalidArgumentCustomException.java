package com.dib.uniba.exception;

public class InvalidArgumentCustomException extends IllegalArgumentException {
    /**
	 * 
	 */
	private static final long serialVersionUID = 8732916822262406012L;

	public InvalidArgumentCustomException(String message) {
        super(message);
    }
}
