FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server python3 python3-apt python3-venv openssl ca-certificates && mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh
RUN printf 'PermitRootLogin yes\nPasswordAuthentication no\nPubkeyAuthentication yes\nUsePAM no\n' > /etc/ssh/sshd_config.d/fixture.conf && passwd -d root
COPY systemctl.py /usr/local/bin/systemctl
RUN chmod 755 /usr/local/bin/systemctl
CMD ["/usr/sbin/sshd", "-D", "-e"]
