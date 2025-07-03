/*
 * Copyright (C) 2021, 2024 Thomas Wolf <twolf@apache.org> and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Distribution License v. 1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
package org.eclipse.jgit.lib;

import java.io.IOException;
import java.util.Date;

import org.eclipse.jgit.annotations.NonNull;
import org.eclipse.jgit.api.errors.JGitInternalException;

/**
 * A {@code SignatureVerifier} can verify signatures on git commits and tags.
 *
 * @since 7.0
 */
public interface SignatureVerifier {

	/**
	 * Verifies a given signature for given data.
	 *
	 * @param repository
	 *            the {@link Repository} the data comes from.
	 * @param config
	 *            the {@link GpgConfig}
	 * @param data
	 *            the signature is for
	 * @param signatureData
	 *            the ASCII-armored signature
	 * @return a {@link SignatureVerification} describing the outcome
	 * @throws IOException
	 *             if the signature cannot be parsed
	 * @throws JGitInternalException
	 *             if signature verification fails
	 */
	SignatureVerification verify(@NonNull Repository repository,
			@NonNull GpgConfig config, byte[] data, byte[] signatureData)
			throws IOException;

	/**
	 * Retrieves the name of this verifier. This should be a short string
	 * identifying the engine that verified the signature, like "gpg" if GPG is
	 * used, or "bc" for a BouncyCastle implementation.
	 *
	 * @return the name
	 */
	@NonNull
	String getName();

	/**
	 * A {@link SignatureVerifier} may cache public keys to speed up
	 * verifying signatures on multiple objects. This clears this cache, if any.
	 */
	void clear();

	/**
	 * A {@code SignatureVerification} returns data about a (positively or
	 * negatively) verified signature.
	 */
	public static class SignatureVerification {
		private final String verifierName;
		private final Date creationDate;
		private final String signer;
		private final String keyFingerprint;
		private final String keyUser;
		private final boolean verified;
		private final boolean expired;
		private final @NonNull TrustLevel trustLevel;
		private final String message;
		
		/**
		 * Creates a new signature verification result
		 * 
		 * @param builder the builder with verification data
		 */
		private SignatureVerification(Builder builder) {
			this.verifierName = builder.verifierName;
			this.creationDate = builder.creationDate;
			this.signer = builder.signer;
			this.keyFingerprint = builder.keyFingerprint;
			this.keyUser = builder.keyUser;
			this.verified = builder.verified;
			this.expired = builder.expired;
			this.trustLevel = builder.trustLevel;
			this.message = builder.message;
		}
		
		/**
		 * @return the name of the verifier that created this verification result
		 */
		public String getVerifierName() {
			return verifierName;
		}
		
		/**
		 * @return date and time the signature was created
		 */
		public Date getCreationDate() {
			return creationDate;
		}
		
		/**
		 * @return the signer as stored in the signature, or {@code null} if unknown
		 */
		public String getSigner() {
			return signer;
		}
		
		/**
		 * @return fingerprint of the public key, or {@code null} if unknown
		 */
		public String getKeyFingerprint() {
			return keyFingerprint;
		}
		
		/**
		 * @return user associated with the key, or {@code null} if unknown
		 */
		public String getKeyUser() {
			return keyUser;
		}
		
		/**
		 * @return whether the signature verification was successful
		 */
		public boolean isVerified() {
			return verified;
		}
		
		/**
		 * @return whether the public key used for this signature verification was expired
		 */
		public boolean isExpired() {
			return expired;
		}
		
		/**
		 * @return the trust level of the public key used to verify the signature
		 */
		public @NonNull TrustLevel getTrustLevel() {
			return trustLevel;
		}
		
		/**
		 * @return human-readable message giving additional information about the outcome
		 */
		public String getMessage() {
			return message;
		}
		
		/**
		 * Builder for SignatureVerification objects
		 */
		public static class Builder {
			private String verifierName;
			private Date creationDate;
			private String signer;
			private String keyFingerprint;
			private String keyUser;
			private boolean verified;
			private boolean expired;
			private @NonNull TrustLevel trustLevel = TrustLevel.UNKNOWN;
			private String message;
			
			/**
			 * @param verifierName the name of the verifier
			 * @return this builder for chaining
			 */
			public Builder verifierName(String verifierName) {
				this.verifierName = verifierName;
				return this;
			}
			
			/**
			 * @param creationDate date and time the signature was created
			 * @return this builder for chaining
			 */
			public Builder creationDate(Date creationDate) {
				this.creationDate = creationDate;
				return this;
			}
			
			/**
			 * @param signer the signer stored in the signature
			 * @return this builder for chaining
			 */
			public Builder signer(String signer) {
				this.signer = signer;
				return this;
			}
			
			/**
			 * @param keyFingerprint fingerprint of the public key
			 * @return this builder for chaining
			 */
			public Builder keyFingerprint(String keyFingerprint) {
				this.keyFingerprint = keyFingerprint;
				return this;
			}
			
			/**
			 * @param keyUser user associated with the key
			 * @return this builder for chaining
			 */
			public Builder keyUser(String keyUser) {
				this.keyUser = keyUser;
				return this;
			}
			
			/**
			 * @param verified whether signature verification was successful
			 * @return this builder for chaining
			 */
			public Builder verified(boolean verified) {
				this.verified = verified;
				return this;
			}
			
			/**
			 * @param expired whether the public key was expired
			 * @return this builder for chaining
			 */
			public Builder expired(boolean expired) {
				this.expired = expired;
				return this;
			}
			
			/**
			 * @param trustLevel the trust level of the public key
			 * @return this builder for chaining
			 */
			public Builder trustLevel(@NonNull TrustLevel trustLevel) {
				this.trustLevel = trustLevel;
				return this;
			}
			
			/**
			 * @param message human-readable message about verification outcome
			 * @return this builder for chaining
			 */
			public Builder message(String message) {
				this.message = message;
				return this;
			}
			
			/**
			 * @return a new SignatureVerification instance
			 */
			public SignatureVerification build() {
				return new SignatureVerification(this);
			}
		}
	}

	/**
	 * The owner's trust in a public key.
	 */
	enum TrustLevel {
		UNKNOWN, NEVER, MARGINAL, FULL, ULTIMATE
	}
}
