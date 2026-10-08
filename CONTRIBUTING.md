# Submitting a package to Ember

Anyone can publish a program for Ember Linux. Package it as described below,
then submit it with the **Submit a package** form on the
[Issues](https://github.com/Cherry-Systems/ember-packages/issues/new/choose) page.
Every submission is virus-scanned automatically. If it passes and follows the
[community package rules](#community-package-rules), it's published to the
community repository straight away, and anyone on Ember can install it with
`ember-pkg install NAME`.

Community packages aren't reviewed by a person, so Ember marks them as
community packages when you install them, and only lets them add new files in
the usual places for programs (see the rules below).

## 1. Check the program can run on Ember

Ember is built on the **musl** C library, not glibc like Ubuntu, Debian and
Fedora. Most programs you download for Linux are built for glibc and **won't
run on Ember**. These do:

- **Static programs**: they carry everything they need inside them. Many Go and
  Rust tools are like this.
- **Programs built for musl**: downloads with `musl` or `alpine` in the name.
- **Scripts**: shell, Python, Perl and so on, as long as Ember has the language
  (see the [package list](https://cherry-systems.github.io/ember-packages/x86_64/index)).

Ember runs on 64-bit Intel and AMD PCs (`x86_64`) only.

To check a program on any Linux PC, run `file` on it:

| `file` says | Runs on Ember? |
|---|---|
| `statically linked` or `static-pie linked` | Yes |
| `interpreter /lib/ld-musl-x86_64.so.1` | Yes, if Ember has the libraries it uses |
| `interpreter /lib64/ld-linux-x86-64.so.2` | No, it's built for glibc |

On Ember itself, `ember-pkg check FOLDER` checks every program in a folder.

For example, ripgrep's `ripgrep-15.2.0-x86_64-unknown-linux-musl.tar.gz` download
works, but bat's `bat-v0.26.1-x86_64-unknown-linux-gnu.tar.gz` doesn't (`gnu` means glibc).

### Building it yourself

If there's no musl or static download, build one:

- **Go**: `CGO_ENABLED=0 go build`
- **Rust**: `rustup target add x86_64-unknown-linux-musl`, then
  `cargo build --release --target x86_64-unknown-linux-musl`
- **C or C++**: build inside Alpine Linux, which also uses musl, and link statically:

  ```sh
  docker run --rm -v "$PWD:/src" -w /src alpine sh -c 'apk add build-base && make LDFLAGS=-static'
  ```

## 2. Package it

There are two ways. Only an Ember package (option B) can be submitted to the
repository; a program archive (option A) is just for installing on your own PC.

### Option A: a program archive (for your own PC)

Put the program in a folder, with its commands in a `bin` folder (or at the top
of the folder), and make a `.tar.gz` of it:

```
mytool-1.2/
  bin/mytool
  README
```

```sh
tar -czf mytool-1.2.tar.gz mytool-1.2
```

`ember-pkg install ./mytool-1.2.tar.gz` puts it in `/opt/mytool` and makes its
commands available to run.

### Option B: an Ember package

An Ember package is a `.tar.xz` containing the files exactly where they go on
the system, plus a small `.PKGINFO` file describing the package:

```
mytool/
  .PKGINFO
  usr/bin/mytool
  usr/share/man/man1/mytool.1
```

`.PKGINFO`:

```
name=mytool
version=1.2-1
description=One line saying what it does
depends=ncurses openssl
```

- **version** is the program's version, a dash, then the package release.
  Start at `-1`; if you re-package the same version, make it `-2`.
- **depends** lists the Ember packages it needs, separated by spaces (leave it
  empty if none). Names are in the
  [package list](https://cherry-systems.github.io/ember-packages/x86_64/index),
  or run `ember-pkg search` on Ember.
- Put programs in `usr/bin`, libraries in `usr/lib`, and other files in
  `usr/share`. See the [community package rules](#community-package-rules) for
  exactly where files may go.

Then build the package:

```sh
mkdir -p mytool/usr/bin
cp path/to/mytool mytool/usr/bin/mytool
chmod 755 mytool/usr/bin/mytool
# write mytool/.PKGINFO as above
tar -C mytool --owner=0 --group=0 -cJf mytool-1.2-1.tar.xz .PKGINFO usr
```

If you have Ember, test it: install what it depends on first
(`ember-pkg install ncurses openssl`), then `ember-pkg install ./mytool-1.2-1.tar.xz`,
run it, and finally `ember-pkg remove mytool`.

## Community package rules

So that a package nobody has reviewed can't take over someone's PC, a
community package may only add **new** files in these places:

- `usr/bin`, `usr/lib`, `usr/libexec`, `usr/share` and `usr/include`
- `opt/NAME` and `etc/NAME`, where NAME is the package's name

It also can't:

- replace a file that's already on the system, or add a command with the same
  name as one Ember already has (in `/bin`, `/sbin` or `/usr/sbin`)
- use the name of one of Ember's own packages
- contain setuid programs, device files or hard links, or files inside a symlink
- contain programs built for glibc or for anything other than 64-bit Intel/AMD

Its dependencies must be Ember packages, official or community. These rules are
checked when you submit, and again by `ember-pkg` on every PC that installs it.

### Updating your package

Submit the new version the same way, with the same name and a different
version (for example `1.2-2` or `1.3-1`). Only the person who first published a
name can update it. PCs pick up the new version with `ember-pkg upgrade`.

## 3. Submit it

1. GitHub only accepts `.zip`, `.tar.gz` and `.tgz` files (up to 25 MB), so put
   your package in a zip first: `zip mytool.zip mytool-1.2-1.tar.xz`.
2. Go to **Issues**, click **New issue**, and choose **Submit a package**.
3. Fill in the form and drag your file into the **Package file** box.
4. Within a couple of minutes, a comment shows the result. If it passed, the
   package is already published. If something needs fixing, the comment says
   what; edit the issue and attach the fixed file to try again.

Make sure the program's license allows it to be shared.

### What's rejected automatically

The file is removed and the submission closed if it contains:

- a virus or other malware (scanned with ClamAV), or a cryptocurrency miner
- a password-protected archive, which can't be checked
- files that would be placed outside the package's own folder
- an "archive bomb" that unpacks to an enormous size
- `/etc/ld.so.preload`, a way of forcing code into every program

If Ember finds a published community package doing something harmful, it's
taken out of the repository.
