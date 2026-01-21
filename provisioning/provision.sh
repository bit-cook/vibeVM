#!/bin/bash
set -eux

apt-get update
apt-get install -y --no-install-recommends      \
        build-essential                         \
        pkg-config                              \
        libssl-dev                              \
        curl                                    \
        git                                     \
        ripgrep

curl https://mise.run | sh
echo 'eval "$(~/.local/bin/mise activate bash)"' >> .bashrc

cat > .bash_logout <<EOF
systemctl poweroff
sleep 100 # sleep here so that we don't see the login screen flash up before the shutdown.
EOF

systemctl poweroff
