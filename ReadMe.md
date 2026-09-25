WTC-Y254THJF

LockGuard — Secure Login System
A secure login system built in Java to demonstrate real-world authentication security: password hashing, brute-force protection, and audit logging — not just a login form that works.
Why This Exists
Most login demos check one thing: does the password match? LockGuard is built around a different question — what happens when someone tries to break it?
Key Security Features
Password hashing — BCrypt (work factor 12), never plaintext or weak reversible hashing
Brute-force protection — account locks after 5 failed login attempts
SQL injection defense — all queries use PreparedStatement, no string concatenation
Password policy enforcement — minimum 8 characters, requires upper/lower/digit/special character
Audit logging — every login attempt (success/failure) is recorded and viewable by admins
Externalized schema — SQL schema lives in schema.sql, not hardcoded in Java
Architecture
SecureLoginSystem  ->  SecurityService  ->  Database
   (console menu)      (hashing, rules,     (SQLite via JDBC)
                        lockout logic)
Class
Responsibility
SecureLoginSystem
Console menu — register, log in, exit; admin sub-menu on admin login
SecurityService
Password hashing, strength/username validation, lockout logic
Database
SQLite connection, user CRUD, login attempt logging
User
Data model — id, username, passwordHash, role, failedAttempts, locked
LoginAttempt
Data model for the audit log
TwoFactorService
Stub only — see "What's Not Included" below
Design Decisions
Choice
Why
BCrypt over SHA-256
BCrypt is deliberately slow — resists offline brute-force even if the database is stolen
Lockout after 5 attempts
Balances usability against online brute-force risk
PreparedStatement everywhere
Eliminates SQL injection as an attack vector by design, not convention
Schema in schema.sql
Keeps data structure separate from logic — easier to audit, easier to change
JUnit 5 test suite, isolated DB
14 automated tests run against a separate test_secure_login.db, deleted before/after each run, so tests never pollute real data or each other
What's Not Included (and Why)
2FA (TOTP) — TwoFactorService.java is fully designed but not wired into the live build. The dev.samstevens.totp dependency could not be reliably resolved in this environment due to a persistent network/DNS issue reaching Maven Central. Documented here rather than hidden or faked.
Network-level protections (rate limiting by IP, HTTPS enforcement) — out of scope for this build
Password reset flow — out of scope for this build
Encryption at rest — database file itself is not the threat model here
Admin promotion is currently manual (direct database update), not exposed through the app
Tech Stack
Java 17 - Maven - SQLite (JDBC) - BCrypt (jBCrypt) - JUnit 5 - Docker
Project Structure
LockGuard/
├── src/
│   ├── main/
│   │   ├── java/com/tshishongatsumbe/securelogin/
│   │   │   ├── Database.java
│   │   │   ├── LoginAttempt.java
│   │   │   ├── SecureLoginSystem.java
│   │   │   ├── SecurityService.java
│   │   │   ├── TwoFactorService.java
│   │   │   └── User.java
│   │   └── resources/
│   │       └── schema.sql
│   └── test/
│       └── java/com/tshishongatsumbe/securelogin/
│           └── SecurityServiceTest.java
├── Dockerfile
├── Makefile
├── pom.xml
└── README.md
Getting Started
Prerequisites
Java 17+
Maven (or use IntelliJ's bundled Maven)
Run it
mvn compile exec:java
Or use the provided Makefile:
make run
Run the tests
mvn test
Or:
make test
Run with Docker
docker build -t lockguard .
docker run -it --rm lockguard
Testing
The project includes a JUnit 5 test suite covering:
Password hashing and verification
Password strength validation
Username validation
Account lockout after 5 failed attempts, and recovery via admin unlock
Duplicate username rejection (database constraint)
Each test run uses an isolated test database (test_secure_login.db), deleted before and after every test, so results are consistent and never depend on leftover state.
License
This project was built as a cybersecurity elective assignment
