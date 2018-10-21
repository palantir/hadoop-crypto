FROM ibmjava:8-sdk
ADD . /workspace
RUN /bin/bash -c "ln -s /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 /usr/lib/ssl/libcrypto.so"
