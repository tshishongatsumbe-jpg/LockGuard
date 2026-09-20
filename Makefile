# LockGuard - Secure Login System
# Wraps common Maven commands for easier use

.PHONY: build run test clean docker-build docker-run

build:
	mvn compile

run:
	mvn exec:java -Dexec.mainClass="com.tshishongatsumbe.securelogin.SecureLoginSystem"

test:
	mvn test-compile
	mvn exec:java -Dexec.classpathScope=test -Dexec.mainClass="com.tshishongatsumbe.securelogin.SecurityServiceTest"

clean:
	mvn clean
	rm -f secure_login.db

docker-build:
	docker build -t lockguard .

docker-run:
	docker run -it --rm lockguard