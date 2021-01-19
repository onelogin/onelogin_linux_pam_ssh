from ubuntu:latest

run mkdir -p /lib/security                                   && \
    mkdir -p /run/sshd                                       && \
    apt update                                               && \
    apt install -y libpam-python openssh-server sudo rsyslog

copy etc/ssh/sshd_config /etc/ssh
copy etc/pam.d/sshd /etc/pam.d
copy src /opt/onepam
copy dependencies /lib/python2.7

run useradd -rm -d /home/admin -s /bin/bash -G sudo admin && \
    useradd -rm -d /home/user -s /bin/bash user                           && \
    echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers           && \
    chmod 600 /opt/onepam/onepam.json

cmd /usr/sbin/rsyslogd; /usr/sbin/sshd -D -E /var/log/sshd.log
