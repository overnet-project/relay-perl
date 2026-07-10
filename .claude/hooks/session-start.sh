#!/bin/bash
# Provision the Overnet Perl toolchain for Claude Code on the web.
#
# The Overnet dists require Perl >= 5.40 (see MIN_PERL_VERSION in Makefile.PL);
# the base image ships only system perl 5.38, so this hook builds perl 5.42
# into /opt/perl-5.42 (matching CLAUDE.md) and installs CPAN dependencies into
# ~/perl5. Both live outside the repo and are cached across web sessions, so
# the expensive build only runs on a cold container.
#
# Idempotent and non-interactive: safe to run repeatedly.
set -euo pipefail

# Only provision in the Claude Code on the web (remote) environment.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# --- Per-repo configuration -------------------------------------------------
# Sibling repo lib/ dirs to place on PERL5LIB (in-tree Overnet::* modules that
# are not on CPAN) and the dists whose dependencies should be installed.
# Mirrors this repo's .github/workflows/test.yml.
SIBLING_LIBS=(core-perl irc-server)
INSTALL_DISTS=(core-perl relay-perl)
NEED_NOSTR_CORE=1   # dists that pull Net::Nostr need this installed first
NEED_STYLE=1        # install overnet-perl-style tooling for xt/author checks
# ---------------------------------------------------------------------------

PERL_PREFIX=/opt/perl-5.42
PERL_VERSION=5.42.0
LOCAL_LIB="$HOME/perl5"
REPO_DIR="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
WORKSPACE="$(cd "$REPO_DIR/.." && pwd)"
export PERL_CPANM_HOME="$HOME/.cpanm"

log() { echo "[session-start] $*"; }

# 1. System build dependencies. libgmp-dev supplies gmp.h, needed to build
#    Math::GMPz -> Crypt::PK::ECC::Schnorr -> Net::Nostr::Core.
if [ ! -e /usr/include/gmp.h ] && [ ! -e /usr/include/x86_64-linux-gnu/gmp.h ]; then
  log "Installing system build dependency: libgmp-dev"
  if command -v sudo >/dev/null 2>&1; then SUDO=sudo; else SUDO=; fi
  DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y libgmp-dev || \
    log "WARNING: could not install libgmp-dev; Net::Nostr::Core may fail to build"
fi

# 2. Build Perl 5.42 if it is not already present (cached across sessions).
if [ ! -x "$PERL_PREFIX/bin/perl" ]; then
  log "Building Perl $PERL_VERSION into $PERL_PREFIX (cold start, a few minutes)..."
  tmp="$(mktemp -d)"
  curl -fsSL "https://www.cpan.org/src/5.0/perl-$PERL_VERSION.tar.gz" -o "$tmp/perl.tar.gz"
  tar xzf "$tmp/perl.tar.gz" -C "$tmp"
  (
    cd "$tmp/perl-$PERL_VERSION"
    ./Configure -des -Dprefix="$PERL_PREFIX" -Dusethreads -Duseshrplib
    make -j"$(nproc)"
    make install
  )
  rm -rf "$tmp"
fi

PERL="$PERL_PREFIX/bin/perl"
export PATH="$PERL_PREFIX/bin:$LOCAL_LIB/bin:$PATH"

# 3. Bootstrap cpanm into the local::lib for this perl.
if [ ! -x "$LOCAL_LIB/bin/cpanm" ]; then
  log "Bootstrapping cpanm into $LOCAL_LIB..."
  mkdir -p "$PERL_CPANM_HOME"
  curl -fsSL https://cpanmin.us -o "$PERL_CPANM_HOME/cpanm"
  "$PERL" "$PERL_CPANM_HOME/cpanm" --local-lib "$LOCAL_LIB" --notest App::cpanminus
fi

cpanm_run() { "$PERL" "$LOCAL_LIB/bin/cpanm" --local-lib "$LOCAL_LIB" --notest "$@"; }

# 4. Assemble PERL5LIB: local::lib + present sibling repo libs.
PERL5LIB_PARTS="$LOCAL_LIB/lib/perl5"
if [ "${#SIBLING_LIBS[@]}" -gt 0 ]; then
  for sib in "${SIBLING_LIBS[@]}"; do
    [ -d "$WORKSPACE/$sib/lib" ] && PERL5LIB_PARTS="$PERL5LIB_PARTS:$WORKSPACE/$sib/lib"
  done
fi
if [ "$NEED_STYLE" = 1 ] && [ -d "$WORKSPACE/overnet-perl-style/lib" ]; then
  # Provides the Overnet::* Perl::Critic policies referenced by .perlcriticrc.
  PERL5LIB_PARTS="$PERL5LIB_PARTS:$WORKSPACE/overnet-perl-style/lib"
fi
export PERL5LIB="$PERL5LIB_PARTS"

# 5. Install CPAN dependencies (mirrors CI).
if [ "$NEED_NOSTR_CORE" = 1 ]; then
  # Net::Nostr::Core is a separate dist that the other Net::Nostr::* dists
  # check for at configure time, so install it explicitly first.
  cpanm_run Net::Nostr::Core
fi
if [ "${#INSTALL_DISTS[@]}" -gt 0 ]; then
  for dist in "${INSTALL_DISTS[@]}"; do
    [ -d "$WORKSPACE/$dist" ] && cpanm_run --installdeps "$WORKSPACE/$dist"
  done
fi
if [ "$NEED_STYLE" = 1 ] && [ -d "$WORKSPACE/overnet-perl-style" ]; then
  cpanm_run --installdeps "$WORKSPACE/overnet-perl-style"
fi

# 6. Persist the environment for the rest of the session.
{
  echo "export PATH=\"$PERL_PREFIX/bin:$LOCAL_LIB/bin:\$PATH\""
  echo "export PERL5LIB=\"$PERL5LIB\""
  echo "export PERL_LOCAL_LIB_ROOT=\"$LOCAL_LIB\""
  echo "export PERL_CPANM_HOME=\"$PERL_CPANM_HOME\""
} >> "$CLAUDE_ENV_FILE"

log "Perl toolchain ready ($($PERL -e 'print $^V'))."
