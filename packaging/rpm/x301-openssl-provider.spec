%bcond_without tests

%global commit 73b30afd26abdf0fb49cca4249750dc812f8f96a
%global shortcommit 73b30af
%global snapshot 20260902
%global source_manifest_sha256 0f98382033e319ac91aa0b17df33a0b0885087cb3c70d8f0010aa925af3f7632
%global openssl_fork_evr 1:4.1.0~dev.1-0.3.git7d9c89d%{?dist}
%global provider_modulesdir %{_libdir}/ossl-modules
%global __provides_exclude_from ^%{provider_modulesdir}/.*\.so$

Name:           x301-openssl-provider
Version:        0.1.0
Release:        0.9.%{snapshot}git%{shortcommit}%{?dist}
Summary:        Experimental X301 key-exchange provider for OpenSSL
License:        Apache-2.0
URL:            https://github.com/ychromosome/x301-openssl-provider
Source0:        %{url}/archive/%{commit}/x301-openssl-provider-%{commit}.tar.gz
Source1:        x301-provider.conf
Source2:        opensslcnf-zz-x301.config
Source3:        README.crypto-policy
Patch0:         0001-Build-X301-shim-with-RPM-native-flags.patch

BuildRequires:  cargo-rpm-macros
BuildRequires:  cargo >= 1.91
BuildRequires:  rust >= 1.91
BuildRequires:  gcc
BuildRequires:  binutils
BuildRequires:  openssl = %{openssl_fork_evr}
BuildRequires:  openssl-devel = %{openssl_fork_evr}

Requires:       openssl-libs%{?_isa} = %{openssl_fork_evr}

# crypto-bigint is a source-bound path dependency.
Provides:       bundled(crate(crypto-bigint)) = 0.7.5
Provides:       bundled(crate(cpufeatures)) = 0.3.0

%description
X301 is an experimental key-exchange algorithm. The provider also exposes the
private-use X301MLKEM1024 TLS 1.3 hybrid group and delegates ML-KEM-1024 to
OpenSSL. This package activates the provider but does not change the global TLS
group preference. X301 is not standardized or FIPS validated.

%package policy
Summary:        Explicit X301 OpenSSL group overlay for laboratory review
BuildArch:      noarch
Requires:       %{name}%{?_isa} = %{version}-%{release}
# Rebuild once after upgrading from releases that installed a local.d file.
Requires(posttrans): crypto-policies-scripts

%description policy
This laboratory package contains an inert OpenSSL policy-fragment example.
It does not change the selected Fedora crypto policy.

%prep
%setup -q -n x301-openssl-provider-%{commit}
env -i PATH=/usr/bin:/bin HOME=%{_builddir} LC_ALL=C \
    ED301_HERMETIC_LAUNCH=1 \
    ED301_SOURCE_MODE=archive \
    ED301_EXPECTED_SOURCE_MANIFEST_SHA256=%{source_manifest_sha256} \
    /bin/sh scripts/verify-source-tree.sh
%autopatch -p1
install -pm 0644 %{SOURCE3} README.crypto-policy
install -pm 0644 %{SOURCE2} opensslcnf-zz-x301.config.example
pushd provider
%cargo_prep -v ../vendor
popd

%build
%set_build_flags
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
sed -i '\| (/|d' cargo-vendor.txt
popd

%install
install -Dpm 0755 provider/target/rpm/libx301.so \
    %{buildroot}%{provider_modulesdir}/x301.so
install -Dpm 0644 %{SOURCE1} \
    %{buildroot}%{_sysconfdir}/pki/tls/openssl.d/x301-provider.conf

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
env OPENSSL_CONF=/dev/null \
    OPENSSL_MODULES=%{buildroot}%{provider_modulesdir} \
    openssl list -provider default -provider x301 \
    -key-exchange-algorithms | grep -F X301 >/dev/null
%endif

%files
%license LICENSE
%license LICENSE.dependencies
%license provider/cargo-vendor.txt
%doc README.md
%doc THIRD_PARTY_NOTICES.md
%config(noreplace) %{_sysconfdir}/pki/tls/openssl.d/x301-provider.conf
%{provider_modulesdir}/x301.so

%files policy
%doc README.crypto-policy opensslcnf-zz-x301.config.example

%posttrans
echo 'WARNING: X301 and X301MLKEM1024 are experimental, non-standardized and not FIPS validated.'
echo 'The provider is active; global TLS group preferences are unchanged.'
exit 0

%posttrans policy
if ! %{_bindir}/update-crypto-policies; then
    echo 'error: failed to remove a previous X301 policy overlay' >&2
    exit 1
fi
echo 'The X301 policy fragment is installed as inert documentation.'
exit 0

%changelog
* Wed Sep 02 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.8.20260902git73b30af
- Pin the X301-only provider and hybrid assurance repairs
- Verify the complete source inventory before applying the Fedora build patch
- Limit the policy overlay to X301MLKEM1024

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.7.20260901git89facb1
- Add the optional laboratory X301 group-overlay policy package

* Tue Sep 01 2026 Martin Wolf <mwolf@adiumentum.com> - 0.1.0-0.6.20260901git89facb1
- Pin the reviewed X301 source and OpenSSL fork
- Keep TLS groups available only through explicit selection
