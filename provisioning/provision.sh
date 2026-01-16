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

echo 'systemctl poweroff' > .bash_logout

systemctl poweroff
