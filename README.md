# honeypod

A High accuracy, low cost, easy deployable tool to defend k8s applications

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Overview
Blue teams in the cloud have many sources of intelligence flooding into their view, including container registry alerts, login analytics, package and container privilege warnings, etc.  More often than not, SRE teams/SOCs must use a combination of guessing and chasing people down (if they are even able to contact the developers) to determine if there is an issue. 

Compounding the problem: cloud security teams do their best to evaluate the security of solutions; BUT- over time these deployments can drift or receive urgent modifications to remedy problems. Often these "adjustments" include loosening network and/or application permissions.

Enter "Honeypod", a low cost, high 'signal to noise ratio' tool for noticing an attacker in your k8s cluster who is gathering intelligence to egress or encrypt data for extortion and/or blackmarket sale.

Honeypod notices probes in your k8s cluster that signal intelligence gathering and a likely attack on your data/application. Using a simple combination of syslog and alert schema, it gives your SOC a high value/high quality alert that something is happening.

## Installation

1. Clone the repository: `git clone https://github.com/storkinsj/honeypod.git`
2. Navigate to the project directory: `cd honeypod`
3. Install the dependencies: `pip install -r requirements.txt`
4. Build Docker: `cd docker; docker build .`

## Usag

1. Include container into your k8s spec using config map to pass syslog and DNS information
      kind: ConfigMap
metadata:
  name: honeypod-configmap
data:
  honeypod-conf.txt: |
    dns-whitelist: <blessed hosts comma separated>
    dns-updstream: <IP address of dns server>
    syslog-siem: <IP address of syslog interface for cloud SIEM>
    syslog-credentials: <optional syslog server credentails>
    container-ip: <optional manual container IP address setting>
      containers:
      - name: honeypod
        image: storkinsj/honeypod:latest
        ports:
        - containerPort: 0
3. Open your web browser and visit: `http://localhost:3000`

## Contributing

Contributions are welcome! Here's how you can contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature/your-feature`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature/your-feature`
5. Open a pull request.

## License

This project is licensed under the [GPL License](LICENSE).
