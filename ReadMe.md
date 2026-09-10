Secure Login System

Structure

SecureLoginSystem (main)
│
├── User (account data)
├── Database (SQLite access
+ login attempt audit log)
  └── SecurityService (BCrypt
  hashing, strength, lockout)

Setup
1. Download two jars to a lib/ folder:

sqlite-jdbc (e.g. sqlite-jdbc-
3.46.0.0.jar ) — Maven Central

jbcrypt (e.g. jbcrypt-0.4.jar ) — Maven
Central, group org.mindrot
2. Compile:
   javac -cp "lib/*" -d out User.java
   Database.java LoginAttempt.java
   SecurityService.java
   SecureLoginSystem.java

3. Run:
   java -cp "out:lib/*"
   securelogin.SecureLoginSystem
   (Windows: use ; instead of : in the
   classpath.)
4. Run the manual tests:
   javac -cp "lib/*:out" -d out
   SecurityServiceTest.java
   java -cp "out:lib/*"
   securelogin.SecurityServiceTest
   A secure_login.db file is created automatically in
   the working directory.
   Threat model
   Defended against:
   Plaintext password exposure — passwords are
   hashed with BCrypt (work factor 12) before
   storage; the DB never holds a recoverable
   password.
   Offline brute-forcing of stolen hashes —

BCrypt is deliberately slow (unlike SHA-
256/MD5), making large-scale hash cracking

expensive.

Online brute-forcing — account locks after 5
failed attempts.
SQL injection — all queries use
PreparedStatement with parameter binding,
never string concatenation.
Weak passwords — registration rejects
passwords under 8 characters or missing
upper/lower/digit/special character classes.
No accountability for failed logins — every
attempt (success or failure) is written to
login_attempts with a timestamp, and an
admin can review a user's recent attempts.
Explicitly out of scope for v1 (worth stating in your
presentation, not hiding):
No network-level protections (this is a local
console app, not a hardened server)
No rate-limiting by IP/device, only by account
No password reset / forgot-password flow
No 2FA
First admin account must be promoted
manually via a direct SQL UPDATE (no
bootstrap admin flow yet)
No encryption at rest for the SQLite file itself
(OS-level disk encryption assumed)
One-minute explanation

"I built a secure login system using Java and
SQLite. The User class represents
users and their account information. The Database
class handles communication
with SQLite, including a login-attempts audit log.
The SecurityService handles
the security features: BCrypt password hashing,
password strength checks, and
account lockout. The main class controls the
application flow. The system
locks an account after five failed login attempts to
protect against
brute-force attacks, and every attempt is logged
for accountability."