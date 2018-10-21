FROM openjdk:8-jdk
RUN apt-get update && apt-get install -y --no-install-recommends openssl
RUN /bin/bash -c "ln -s /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.2 /usr/lib/ssl/libcrypto.so"
