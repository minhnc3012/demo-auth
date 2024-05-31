package com.example.demo.exceptions;

/**
 * Thrown when an error occurred during the tenant resolution process.
 */
public class TenantResolutionException extends IllegalStateException {
	private static final long serialVersionUID = 1L;

	public TenantResolutionException() {
		super("Error when trying to resolve the current tenant");
	}

	public TenantResolutionException(String message) {
		super(message);
	}

}
