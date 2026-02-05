FROM alpine:latest

RUN apk add --no-cache git openssh bash

# Setup git user (SSH key authentication only, no password)
RUN adduser -D -h /var/lib/git -s /bin/sh git && \
    passwd -u git && \
    mkdir -p /var/lib/git && \
    chown -R git:git /var/lib/git

# Configure SSH - key-based authentication only
RUN ssh-keygen -A && \
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication no" >> /etc/ssh/sshd_config

# Prepare authorized_keys
RUN mkdir -p /var/lib/git/.ssh && \
    touch /var/lib/git/.ssh/authorized_keys && \
    chmod 700 /var/lib/git/.ssh && \
    chmod 600 /var/lib/git/.ssh/authorized_keys && \
    chown -R git:git /var/lib/git/.ssh

COPY init-repo.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/init-repo.sh

EXPOSE 22
CMD ["/usr/local/bin/init-repo.sh"]
