package com.example.demo.exceptions;

/**
 * Thrown when no tenant information is found in a given context.
 */
public class TenantNotFoundException extends IllegalStateException {
	
	private static final long serialVersionUID = 1L;

	public TenantNotFoundException() {
        super("No tenant found in the current context");
    }

    public TenantNotFoundException(String message) {
        super(message);
    }

}
