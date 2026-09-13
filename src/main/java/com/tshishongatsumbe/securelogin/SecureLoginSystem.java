package com.tshishongatsumbe.securelogin;

import java.util.List;
import java.util.Scanner;

/**
 * Controls the application flow and uses SecurityService + Database
 * to perform registration, login, lockout, 2FA, and admin operations.
 */
public class SecureLoginSystem {
    private final Database database;
    private final SecurityService securityService;
    private final TwoFactorService twoFactorService;
    private final Scanner scanner;

    public SecureLoginSystem() {
        this.database = new Database();
        this.securityService = new SecurityService(database);
        this.twoFactorService = new TwoFactorService();
        this.scanner = new Scanner(System.in);
    }

    public static void main(String[] args) {
        new SecureLoginSystem().run();
    }

    public void run() {
        boolean running = true;
        while (running) {
            printMenu();
            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1":
                    register();
                    break;
                case "2":
                    login();
                    break;
                case "3":
                    running = false;
                    System.out.println("Goodbye!");
                    break;
                default:
                    System.out.println("Invalid option, try again.");
            }
        }
        database.close();
    }

    private void printMenu() {
        System.out.println("========================");
        System.out.println("      SECURE LOGIN");
        System.out.println("========================");
        System.out.println("1. Register");
        System.out.println("2. Login");
        System.out.println("3. Exit");
        System.out.print("Choose an option: ");
    }

    private void register() {
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        if (!securityService.isValidUsername(username)) {
            System.out.println("Invalid username. Use 3-20 characters: letters, digits, underscore only.");
            return;
        }

        if (database.findUserByUsername(username) != null) {
            System.out.println("That username is already taken.");
            return;
        }

        System.out.print("Password: ");
        String password = scanner.nextLine();

        if (!securityService.isPasswordStrong(password)) {
            System.out.println("Password too weak. Use 8+ characters with upper, lower, digit and special character.");
            return;
        }

        String hash = securityService.hashPassword(password);
        User user = new User(username, hash, "USER");
        if (database.saveUser(user)) {
            System.out.println("Account created successfully!");
            offerTwoFactorSetup(username);
        } else {
            System.out.println("Registration failed.");
        }
    }

    private void offerTwoFactorSetup(String username) {
        System.out.print("Enable two-factor authentication now? (y/n): ");
        String choice = scanner.nextLine().trim();
        if (!choice.equalsIgnoreCase("y")) return;

        User user = database.findUserByUsername(username);
        String secret = twoFactorService.generateSecret();
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        database.updateUser(user);

        System.out.println("Scan this into your authenticator app (or enter the secret manually):");
        System.out.println(twoFactorService.buildOtpAuthUri(username, secret));
        System.out.println("Secret key: " + secret);
    }

    private void login() {
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Password: ");
        String password = scanner.nextLine();

        SecurityService.LoginResult result = securityService.attemptLogin(username, password);

        if (result.success && result.user.isTwoFactorEnabled()) {
            if (!verifyTwoFactorCode(result.user)) {
                System.out.println("Two-factor verification failed. Login denied.");
                return;
            }
        }

        System.out.println(result.message);

        if (result.success && result.user.isAdmin()) {
            adminMenu();
        }
    }

    private boolean verifyTwoFactorCode(User user) {
        System.out.print("Enter your 6-digit authenticator code: ");
        String code = scanner.nextLine().trim();
        return twoFactorService.verifyCode(user.getTwoFactorSecret(), code);
    }

    private void adminMenu() {
        System.out.println("--- Admin options ---");
        System.out.println("1. Unlock a user");
        System.out.println("2. View recent login attempts for a user");
        System.out.println("3. Back to main menu");
        System.out.print("Choose an option: ");
        String choice = scanner.nextLine().trim();

        if (choice.equals("1")) {
            System.out.print("Username to unlock: ");
            String target = scanner.nextLine().trim();
            if (securityService.unlockUser(target)) {
                System.out.println("User '" + target + "' has been unlocked.");
            } else {
                System.out.println("User not found.");
            }
        } else if (choice.equals("2")) {
            System.out.print("Username: ");
            String target = scanner.nextLine().trim();
            List<LoginAttempt> attempts = database.getRecentAttempts(target, 10);
            if (attempts.isEmpty()) {
                System.out.println("No attempts logged for that user.");
            } else {
                attempts.forEach(System.out::println);
            }
        }
    }
}