# Vibe

Vibe is a quick, zero-configuration way to spin up a Linux virtual machine on Mac to sandbox LLM agents:

```
cd my-project/
vibe
# wait ~5 seconds
# you are now in a Linux VM, which has shared access to your my-project/ folder
```

Dependencies:

- An M-series Mac running MacOS 13 (Ventura) or higher.
- A network connection is required on the first run to download and configure the Debian Linux base image.
- That's it!


## Install

Vibe is a single binary, so it's easy to install.

If you use the excellent [mise-en-place](https://mise.jdx.dev/), it can download the pre-complied binary from Github for you:

    mise use github:lynaghk/vibe@latest
    
Or you can grab the binary yourself and put it on your `$PATH`.

Alternatively, if you want to modify it for your own needs, all you need is a Rust toolchain:

    git clone ssh://git@github.com:lynaghk/vibe
    cd vibe
    cargo install


## Command reference


vibe --expand

vibe configure provisioning-bash-script.sh

vibe --mount host-path:guest-path

if `host-path` doesn't exist, it will be created.

--no-default-mounts
--no-mask-git




--mount 





## How it works

The first time you run `vibe` on your computer, a Debian Linux image is downloaded to `~/.cache/vibe/` and configured with basic tools like gcc, [mise-en-place](https://mise.jdx.dev/), ripgrep, etc.
(See `/src/provision.sh` for details.)

Then, when you run `vibe` in a project directory, it makes a copy of this configured image to `.vibe/instance.raw`, boots it up, and attaches your terminal to this VM.
When you `exit` this shell, the VM is shutdown.
The VM disk persists in the `.vibe` folder.

The VM disks are 10 GB, but because Apple Filesystem is copy-on-write, disk space is only actually consumed when new data is written.
You can use `du -h` to see how much space is actually consumed:

    $ ls -lah .vibe/
    Permissions Size User Date Modified Name
    .rw-r--r--   11G dev  18 Jan 12:52   instance.raw

    $ du -h .vibe/instance.raw
    1.2G    .vibe/instance.raw
    

Other tricks:

- MacOS only lets binaries signed with the `com.apple.security.virtualization` entitlement run virtual machines, so `vibe` checks itself on startup and, if necessary, signs itself using `codesign`. SeCuRiTy!



## Alternatives

I started this project in 2026 Jan after I noticed OpenAI's codex agent reading files outside of the folder I'd started it in (not cool, bro!).
Here's what I tried before writing this solution:

- [Sandboxtron](https://github.com/lynaghk/sandboxtron/) - My own little wrapper around Mac's `sandbox-exec`.
Turns out both Claude Code and Codex rely on this as well, and MacOS doesn't allow creating a sandbox from within a sandbox.
I considered writing my own sandboxing rules and running the agents `--yolo`, but didn't like the risk of configuration typos and/or Mac sandbox escapes (there are a lot --- I'm not an expert, but from [this HN discussion](https://news.ycombinator.com/item?id=42084588) I figured virtualization would be safer).
- [Lima](https://github.com/lima-vm/lima/), quick Linux VMs on Mac. I wanted to like this, ran into too many issues in first 30 minutes to trust it:
  - The recommended Debian image took 8 seconds to get to a login prompt, even after the VM was already running.
  - The CLI flags *mutate hidden state*. E.g., If you `limactl start --mount foo` and then later `limactl start --mount bar`, both `foo` and `bar` will be mounted.
  - Some capabilities are only available via yaml. E.g., the `--mount` CLI flag always mounts at the same path in the guest. If you want to mount at a different path, you have to do that via YAML.
  - There's some kind of inheritance happening so even if you do write YAML, you can't see the full configuration.
  
- [Vagrant](https://developer.hashicorp.com/vagrant/) - I fondly remember using this back in the early 2010's, but based on this [2025 Reddit discussion](https://www.reddit.com/r/devops/comments/1axws75/vagrant_doesnt_support_mac_m1/) it seemed like running it on an ARM-based Mac was A Project and so I figured it'd be easier to roll my own thing.

- [Tart](https://tart.run/) - I found this via some positive HN comments, but unfortunately wasn't able to run the release binary from their GitHub because it's not signed.
They apparently hack around that when installing with homebrew, but I don't use homebrew either.
I tried cloning the repo and compiling myself, but the build failed with lots of language syntax errors despite the repo SHA is the same as one of their releases.
I assume this is a Swift problem and not Tart's, since this sort of mess happens most times when I try to build Swift. `¯\_(ツ)_/¯`

- [OrbStack](https://orbstack.dev/) - This looked nice, but seems mostly geared towards container stuff.
It runs a single VM, and I couldn't figure out how to have this VM run *without* my entire disk mounted inside of it.
I didn't want to run agents via containers, since containers aren't security boundaries.

- [Apple Container Framework](https://github.com/apple/container) - This looks technically promising, as it runs every container within a lightweight VM.
Unfortunately it requires MacOS 26 Tahoe, which wrecks [window resizing](https://news.ycombinator.com/item?id=46579864), adds [useless icons everywhere](https://news.ycombinator.com/item?id=46497712), and otherwise seems to be a mess.
Sorry excellent Apple programmers and hardware designers, I hope your management can reign in the haute couture folks before we all have to switch to Linux for professional computing.

- [QEMU](https://wiki.qemu.org/) - The first prototype of this app was a single bash script wrapping `qemu`. This worked swimmingly, except for host/guest folder sharing, which ended up being a show-stopper. This is because QEMU doesn't support [virtiofs](https://virtio-fs.gitlab.io/) on Mac hosts, it only supports "9p", which is way slower ---  e.g., `mise use node@latest` takes > 10 minutes on 9p and 5 seconds on virtiofs.


## Roadmap / Collaboration

I wrote this software for myself, and I'm open to pull requests and otherwise collaborating on features that I'd personally use:

- forwarding ports from the host to a guest
- running `vibe` in a folder that already has a vibe VM running should connect to the already-running VM
  - the VM shouldn't shutdown until all host terminals have logged out
- if not the above, at least a check and nice error message when you try to start a VM that's already running.
- a way to make faster-booting even more minimal Linux virtual machines
  - this should be bootstrappable on Mac; i.e., if the only way to make a small Linux image is with Linux-only tools, the entire process should still be runnable on MacOS via intermediate VMs


I'm not sure about (but open to discussing proposals via GitHub issues):

- the ability to run VMs in the background
- the ability to script VMs

I'm not interested in:

- anything related to Docker / containers / Kubernetes / distributed systems
- supporting other host or guest operating systems
