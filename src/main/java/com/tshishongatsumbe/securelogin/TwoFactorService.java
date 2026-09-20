package com.tshishongatsumbe.securelogin;

/**
 * Handles TOTP-based two-factor authentication: generating secrets
 * and verifying 6-digit codes from an authenticator app.
 *
 * NOTE: Not currently wired into SecureLoginSystem. The full
 * implementation used the dev.samstevens.totp library, but a
 * dependency resolution issue in this environment prevented it
 * from building reliably. This stub preserves the intended design
 * and method signatures.
 */
public class TwoFactorService {

    private static final String ISSUER = "LockGuard";

    public String generateSecret() {
        // Full implementation would use dev.samstevens.totp's
        // SecretGenerator to produce a random Base32 secret.
        throw new UnsupportedOperationException("2FA not enabled in this build.");
    }

    public boolean verifyCode(String secret, String code) {
        // Full implementation would use dev.samstevens.totp's
        // CodeVerifier to check a 6-digit TOTP code against the secret.
        throw new UnsupportedOperationException("2FA not enabled in this build.");
    }

    public String buildOtpAuthUri(String username, String secret) {
        return "otpauth://totp/" + ISSUER + ":" + username +
                "?secret=" + secret + "&issuer=" + ISSUER;
    }
}