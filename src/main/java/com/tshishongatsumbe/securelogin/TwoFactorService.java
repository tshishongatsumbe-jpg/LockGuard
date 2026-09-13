package com.tshishongatsumbe.securelogin;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

/**
 * Handles TOTP-based two-factor authentication: generating secrets
 * and verifying 6-digit codes from an authenticator app (Google
 * Authenticator, Authy, etc).
 */
public class TwoFactorService {

    private static final String ISSUER = "LockGuard";

    private final SecretGenerator secretGenerator = new DefaultSecretGenerator();
    private final TimeProvider timeProvider = new SystemTimeProvider();
    private final CodeVerifier codeVerifier =
            new DefaultCodeVerifier(new DefaultCodeGenerator(HashingAlgorithm.SHA1), timeProvider);

    public String generateSecret() {
        return secretGenerator.generate();
    }

    public boolean verifyCode(String secret, String code) {
        if (secret == null || code == null) return false;
        return codeVerifier.isValidCode(secret, code);
    }

    /**
     * Builds the otpauth:// URI the user can type/scan into an
     * authenticator app. In a console app we just print this string
     * (or the raw secret) instead of rendering a QR code image.
     */
    public String buildOtpAuthUri(String username, String secret) {
        return "otpauth://totp/" + ISSUER + ":" + username +
                "?secret=" + secret + "&issuer=" + ISSUER;
    }
}