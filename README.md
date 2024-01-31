# honeypod

A High accuracy, low cost, easy deployable tool to defend k8s applications

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Overview
Blue teams in the cloud have many sources of intelligence flooding into their view, including container registry alerts, login analytics, Kubernetes and container privilege warnings, etc.  More often than not, SRE teams/SOCs use a combination of guessing and chasing people to determine if there is an issue. 

Compounding the problem: cloud security teams do their best to evaluate the security of solutions; BUT- over time these deployments can drift or receive urgent modifications to remedy problems. These "adjustments" may include loosening network permissions. Sometimes these are "temporary" changes that become "permanent".

Enter "Honeypod", a low cost, high 'signal to noise ratio' tool for noticing an attacker in your k8s cluster who is gathering intelligence to egress or encrypt data for extortion or dark web sales.

Honeypod can notice "probes" in your k8s cluster that signal intelligence gathering and a likely attack on your data/application. Using a simple combination of syslog and alert schema, it gives your SOC a high value/high quality alert that something is happening.

## Installation

1. Clone the repository: `git clone https://github.com/storkinsj/honeypod.git`
2. Navigate to the project directory and install the dependencies: `pip install -r requirements.txt`
3. Build container:  `docker build . -f docker/Dockerfile`
4. set appropriate env settings; i.e.:
```bash
export dnsServer=192.168.0.1 (an upstream dns server)
export dnsForwarder=172.17.0.1 (an upstream dns server)
export HONEYPOD_WHITELIST=myredisinstance,mybackendserver,myCloudserviceIP, <any connection your k8s workload must make must be in here>
export syslogServer=<host name for your SIEM or syslog server to watch for "HONEYPOD" messages>
export HONEYPOD_LOG="/var/log/honeypod" (Alternatively use a cloud storage mount here)
```
Your corresponding ConfigMap would include:
```yaml
kind: ConfigMap
metadata:
  name: honeypod-configmap
data:
  honeypod-conf.txt: |
    HONEYPOD_WHITELIST: <blessed hosts comma separated>
    dnsServer: <IP address of dns server>
    syslogServer: <IP address of syslog interface for cloud SIEM>
    HONEYPOD_LOG: <defaults to "/var/log/honeypod"; can set to shared storage)
...
```
## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request.

## License

This project is licensed under the [GPL License](LICENSE).
