## AutoDNS provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [AutoDNS](https://de.autodns.com/domain-robot-api/).

### Installation

#### Command line

```
pip install octodns-autodns
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-autodns==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-autodns.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_autodns
```

### Configuration

```yaml
providers:
  autodns:
    class: octodns_autodns.AutoDNSProvider
    username: env/username
    password: env/password
    context: 4
```

### Support Information

#### Records

AutoDNSProvider supports A, AAAA, CAA, TXT, CNAME, MX, NS, SRV, ALIAS

#### Dynamic

AutoDNSProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
