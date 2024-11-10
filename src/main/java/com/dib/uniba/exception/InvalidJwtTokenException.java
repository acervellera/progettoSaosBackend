package com.dib.uniba.exception;

public class InvalidJwtTokenException extends RuntimeException {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public InvalidJwtTokenException(String message) {
        super(message);
    }
}