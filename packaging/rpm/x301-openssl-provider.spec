%bcond_without tests

%global commit a695bb2bbdf027c93c1e5a0f9337e508211b4498
%global shortcommit a695bb2
%global snapshot 20260901
%global source_manifest_sha256 2c75423ea3f10fe461eeb0a6563c9474ac1bf290e8038a08d5c0914821951ffb
%global provider_modulesdir %{_libdir}/ossl-modules
%global __provides_exclude_from ^%{provider_modulesdir}/.*\.so$

Name:           x301-openssl-provider
Version:        0.1.0
Release:        0.3.%{snapshot}git%{shortcommit}%{?dist}
Summary:        Experimental X301 key-exchange provider for OpenSSL
License:        Apache-2.0
URL:            https://github.com/ychromosome/x301-openssl-provider
Source0:        %{url}/archive/%{commit}/x301-openssl-provider-%{commit}.tar.gz
Source1:        x301-provider.conf
Source2:        opensslcnf-x301.config
Source3:        x301-crypto-policy
Source4:        ssl-ctx-policy-probe.c
Source5:        README.crypto-policy
Source6:        x301-crypto-policy.8
Patch0:         0001-Build-X301-shim-with-RPM-native-flags.patch

BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo >= 1.91
BuildRequires:  rust >= 1.91
BuildRequires:  gcc
BuildRequires:  binutils
BuildRequires:  pkgconfig(openssl) >= 3.5.7
%if %{with tests}
BuildRequires:  openssl
%endif

Requires:       openssl-libs%{?_isa} >= 1:3.5.7
Requires:       bash
Requires:       coreutils
Requires:       crypto-policies-scripts
Requires:       gawk
Requires:       util-linux
Requires(posttrans): crypto-policies-scripts
Requires(postun): crypto-policies-scripts

%description
X301 is an experimental key-exchange algorithm. The provider also exposes the
private-use X301MLKEM1024 TLS 1.3 hybrid group and delegates ML-KEM-1024 to
OpenSSL. Installing this package activates the provider system-wide and places
X301MLKEM1024 and X301 ahead of the selected crypto-policy TLS group list.
X301 is not standardized or FIPS validated.

%prep
%setup -q -n x301-openssl-provider-%{commit}
test "$(sha256sum SOURCE_MANIFEST.sha256 | awk '{ print $1 }')" = \
    %{source_manifest_sha256}
sha256sum --strict --quiet -c SOURCE_MANIFEST.sha256
%autopatch -p1
install -pm 0644 %{SOURCE5} README.crypto-policy
pushd provider
%cargo_prep -v ../vendor
popd

%build
%set_build_flags
%{__cc} %{build_cflags} -std=c11 -Wall -Wextra -Werror \
    -o x301-openssl-policy-probe %{SOURCE4} \
    %{build_ldflags} $(pkg-config --cflags --libs openssl)
pushd provider
export CC=/usr/bin/gcc
export AR=/usr/bin/ar
export X301_HERMETIC_PROVIDER_BUILD=1
export X301_ALLOW_PACKAGE_BUILD_FLAGS=1
export OPENSSL_INCLUDE_DIR=%{_includedir}
export OPENSSL_LIB_DIR=%{_libdir}
export CARGO_INCREMENTAL=0
%cargo_build -f tls-x301-mlkem1024 -- -p x301-provider

pushd crates/x301-provider
%cargo_license_summary -f tls-x301-mlkem1024
%{cargo_license -f tls-x301-mlkem1024} > ../../../LICENSE.dependencies
popd
%cargo_vendor_manifest
# Fedora 43 cargo2rpm includes workspace path packages in this file although
# the bundled-crate generator accepts registry entries only.
sed -i '\| (/|d' cargo-vendor.txt
popd

%install
install -Dpm 0755 \
    provider/target/rpm/libx301.so \
    %{buildroot}%{provider_modulesdir}/x301.so
install -Dpm 0755 %{SOURCE3} %{buildroot}%{_sbindir}/x301-crypto-policy
install -Dpm 0755 x301-openssl-policy-probe \
    %{buildroot}%{_libexecdir}/x301-openssl-policy-probe
install -Dpm 0644 %{SOURCE6} \
    %{buildroot}%{_mandir}/man8/x301-crypto-policy.8
install -Dpm 0644 %{SOURCE1} \
    %{buildroot}%{_sysconfdir}/pki/tls/openssl.d/x301-provider.conf
install -Dpm 0644 %{SOURCE2} \
    %{buildroot}%{_sysconfdir}/crypto-policies/local.d/opensslcnf-zz-x301.config

%check
%if %{with tests}
env CARGO_HOME=.cargo CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 \
    RUSTFLAGS='%{build_rustflags}' \
    /usr/bin/cargo test --release --locked --offline \
        -p ed301-eddsa --features x301

test_dir=target/rpm-package-tests
mkdir -p "$test_dir"
for harness in provider_x301_contract provider_x301_hybrid_contract \
        provider_x301_nested_properties; do
    %{__cc} %{build_cflags} -std=c11 -Wall -Wextra -Werror -pthread \
        -I%{_includedir} \
        -o "$test_dir/$harness" "provider-tests/x301/$harness.c" \
        %{build_ldflags} -lcrypto
done

module=%{buildroot}%{provider_modulesdir}/x301.so
test -f "$module"
test "$(nm -D --defined-only "$module" \
    | awk '$2 == "T" { count++ } END { print count + 0 }')" -eq 1
nm -D --defined-only "$module" | grep -E ' T OSSL_provider_init$' >/dev/null
if readelf -d "$module" | grep -Eq '\((RPATH|RUNPATH)\)'; then
    echo 'provider module contains an RPATH or RUNPATH' >&2
    exit 1
fi
if strings "$module" \
        | grep -E 'X301_PROVIDER_((PANIC|ALLOC)_FAILPOINT|PUBLIC_ALIAS_MASK)' \
            >/dev/null; then
    echo 'ordinary provider module contains a test hook' >&2
    exit 1
fi

env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=%{buildroot}%{provider_modulesdir} \
    X301_PROVIDER_FAILPOINT_MODE=inert \
    "$test_dir/provider_x301_contract" \
    %{buildroot}%{provider_modulesdir}
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=%{buildroot}%{provider_modulesdir} \
    "$test_dir/provider_x301_hybrid_contract" \
    %{buildroot}%{provider_modulesdir}
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=%{buildroot}%{provider_modulesdir} \
    "$test_dir/provider_x301_nested_properties" \
    %{buildroot}%{provider_modulesdir}
openssl list -provider-path %{buildroot}%{provider_modulesdir} \
    -provider default -provider x301 \
    -key-exchange-algorithms | grep -F X301 >/dev/null
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license provider/cargo-vendor.txt
%doc README.md
%doc THIRD_PARTY_NOTICES.md
%doc README.crypto-policy
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/x301-provider.conf
%config(noreplace) %{_sysconfdir}/crypto-policies/local.d/opensslcnf-zz-x301.config
%{_sbindir}/x301-crypto-policy
%{_libexecdir}/x301-openssl-policy-probe
%{_mandir}/man8/x301-crypto-policy.8*
%{provider_modulesdir}/x301.so

%posttrans
if %{_sbindir}/x301-crypto-policy reconcile; then
    echo 'WARNING: X301 and X301MLKEM1024 are experimental, non-standardized and not FIPS validated.'
    echo 'The provider and TLS groups are active system-wide for newly started OpenSSL applications.'
    echo 'Use "x301-crypto-policy set POLICY" for later crypto-policy transitions.'
    echo 'Direct update-crypto-policies changes bypass this safeguard.'
else
    echo 'ERROR: X301 crypto-policy state could not be verified.' >&2
    echo 'Run "x301-crypto-policy reconcile" before restarting OpenSSL consumers.' >&2
    exit 1
fi
exit 0

%postun
if [ "$1" -eq 0 ] && [ -x %{_bindir}/update-crypto-policies ]; then
    %{_bindir}/update-crypto-policies >/dev/null 2>&1 || :
fi
exit 0

%changelog
* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.3.20260901gita695bb2
- Add the x301-crypto-policy(8) manual page

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.2.20260901gita695bb2
- Rename the hybrid group to X301MLKEM1024 for OpenSSL X-family consistency

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.1.20260901gitf44784c
- Initial split X301 provider package
