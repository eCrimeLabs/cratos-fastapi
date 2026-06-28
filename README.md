[<center><img src="cratos_logo.png" width="250"/></center>](logo)


-------------------------------------------

[MISP Threat Sharing Platform](https://misp-project.org/) is a great platform for collecting and maintaining your CTI/Incident Response findings and context — useful well beyond sharing, in daily hunting engagements, incident response cases, and standard SecOps work.

The CRATOS proxy API sits in front of one or more MISP instances and lets you extract indicators in a format your security components — SIEM, DNS security solutions, proxies, firewalls, EDR, NDR, and anything else that can consume an indicator feed — can act on directly.

---

# Key Features

Threat intelligence sitting in MISP only has value once it reaches the controls that act on it — otherwise it's just expensive data storage. Cratos closes that gap without handing every consuming team or product a MISP API key:

- **Consumers never touch MISP** — firewalls, SIEMs, proxies, EDR/NDR platforms, and mail gateways call Cratos endpoints to pull indicator lists; they get the indicators, never MISP credentials or event context.
- **Tag-based feed classification** — maps your existing MISP tagging conventions to clean API endpoints (`incident`, `alert`, `block`, `hunt`, plus up to 5 custom feeds per site) without requiring you to restructure how your team already classifies intelligence.
- **Scoped, per-consumer tokens** — each token is bound to a specific MISP instance, IP range(s), and expiry date, so a leaked or rotated token has a contained blast radius instead of exposing your whole MISP instance.
- **Multi-tenant by design** — one Cratos instance can front multiple MISP instances, each with its own tag prefix, custom feeds, allowed IPs, and blacklisted tokens.
- **Output format that matches the consumer** — txt, JSON, XML, YAML, or base64, plus vendor-aware formatting (e.g. PaloAlto EDL-compatible output) where a product's ingestion requirements differ from the raw indicator value.
- **Age-based filtering and optional caching** — pull only indicators created/modified within a chosen window, with memcached-backed caching so repeated requests for the same feed don't hammer your MISP backend.

---

# Common Use Cases
The below is just inspiration and you can ingest the data where applicable.

- Ingest data into your protection pipeline
    - Firewall(s) - Active blocking
    - Mail gateway - Active blocking
    - AV product(s) - Active blocking
    - EDR product(s) - Active blocking or Passive detection
    - Proxy product(s) - Active blocking
    - SIEM solution(s) - Passive detection
- Provide a feed to your vulnerability team


---

# How do I get set up?

The below guide has been tested and validated on Debian and Ubuntu, it is recommended to create a virtual environment

## Debian / Ubuntu

We recommend to git clone the Cratos FastAPI into the system to more easily be able to update when updates arrive.

```bash 
$ sudo apt install git python3-venv python3-pip memcached
$ cd /opt
$ git clone https://github.com/eCrimeLabs/cratos-fastapi.git
$ cd cratos-fastapi
$ python3 -m venv .venv
$ source .venv/bin/activate
$ pip install -r requirements.txt
```

## Cratos FastAPI Configurable Files

We will start here as the dependencies to the code running will be used later.

| filename/folder      | Description |
| -------------------- | ------------------------------------------------------------------- |
| log_conf.yaml        | This is the logging configuration file for uvicorn                  |
| config/config.yaml   | Contains the core configurations                                    |
| gunicorn_config.py   | Production-ready Gunicorn configuration with memory management      |
| sites/\<fqdn\>.yaml  | This contains the configuration files related to each MISP instance |

### config/config.yaml

Here is a oneliner that can be used to to create an encryption key

```
openssl rand -base64 4096 | sha256sum | tr '[:lower:]' '[:upper:]'
```

Copy the SHA256 string into the "encryption_key" field.

for the "salt" it will be similar:
```
< /dev/urandom tr -dc 'A-Za-z0-9!#?' | head -c 32; echo
```

Now update the "config/config.yaml" and save.
```yaml
---

debug: False
encryption_key: "<GENERATE ME>"
salt: "<GENERATE ME>"
memcached_user: ""
memcached_pass: ""
memcached_host: "127.0.0.1"
memcached_port: "11211"
access_log: "cratos_access.log"
access_log_max_bytes: 10
access_log_rotations: 5
reverse_proxy: False
reverse_proxy_header: "X-Forwarded-For"
reverse_proxy_real_ip_regex: "^(.*)$"
reverse_proxy_regex_place: 1
allways_allowed_ips:
  - "100.64.3.0/24"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"

```

**Configuration Notes:**
- `access_log`: Path to access log file
- `access_log_max_bytes`: Maximum log file size in MB before rotation
- `access_log_rotations`: Number of backup log files to keep
- `reverse_proxy`: Set to `True` if behind a reverse proxy (nginx, Apache, etc.)
- `reverse_proxy_header`: Header containing real client IP (commonly "X-Forwarded-For" or "X-Real-IP")
- `allways_allowed_ips`: Globally allowed IPs for all sites (typically monitoring systems)

## Configuring your first MISP connection config

In the folder sites you generate a file with the name "\<FQDN\>.yaml" this can also be "\<IP\>.yaml" but it has to map the MISP instance, as it is used as one of the validators if Cratos FastAPI is allowed to connect to this instance and how.

The configuration files are located in the folder "sites"

### misp.example.net

So in this scenario our MISP instance is "misp.example.net" so we create the file in the sites folder:

```bash
$ touch sites/misp.example.net.yaml
```

Now edit the file:

```yaml
---

enabled: true
debug: false
company: Example ApS
tag: example
mispVerifyCert: true
mispTimeoutSeconds: 100
mispDebug: true
memcached_all_timeout: 300
falsepositive_timeout: "1w"
list_stats: "1w"
allowed_ips:
  - "10.0.0.0/8"
  - "127.0.0.1/32"
  - "192.168.1.0/24"
custom_feeds:
  cust1: ":incident-classification=cust1"
  cust2: ":incident-classification=cust2"
  cust3: ":incident-classification=cust3"
  cust4: ":incident-classification=cust4"
  cust5: ":incident-classification=cust5"

```

The field from the "tag" combined with some built-in feeds and 5 custom feeds will be mapped towards the tagging system, so with this setup you will have the following tags that map to these overall feed groups.

| feed name/group | MISP tags you must create (Remember to lock the tags to your organization) |
| --------------- | ------------------------------------------------------------------- |
| incident        | example:incident-classification=incident           |
| alert           | example:incident-classification=alert              |
| block           | example:incident-classification=block              |
| hunt            | example:incident-classification=hunt               |
| cust1           | example:incident-classification=sinkhole           |
| cust2           | example:incident-classification=permanent-block    |
| cust3           | example:incident-classification=tor-exitnode       |
| cust4           | example:incident-classification=cust4              |
| cust5           | example:incident-classification=cust5              |

## Installing system dependencies

```bash
$ sudo apt install nginx libnginx-mod-http-headers-more-filter supervisor gcc openssl libssl-dev python3-dev python3-venv
```

## Configure reverse proxy settings if used 

In the 'config.yaml' file there are the following two options
- reverse_proxy (Boolean)
- reverse_proxy_header (String)

in the event that no reverse proxy is used in front of the API set the "reverse_proxy: False", else if "True" ensure that the 
correct reverse proxy header key that contains the real source IP.

Known headers that reverse proxies are seen using:
- X-Forwarded-For
- X-Real-IP

## Memcached (Optional)
This is "Optional" in the event that you are using an already existing memcached server or cluster

Ensure that memcached is running and enabled at reboot

```bash
sudo apt install memcached libmemcached-tools
sudo systemctl status memcached
sudo systemctl enable memcached
```

Be sure to add enough memory in the memcached config to store the data 

File: "/etc/memcached.conf" and look for below option "-m"
```
# memory (Allocated in MB)
-m 4096
```

If modifying this file remember to restart the service
```bash
sudo systemctl restart memcached
```

## Add the fastapi user

The user must be named `fastapi` to match `gunicorn_config.py`/`gunicorn.service_example`, which both reference `user = 'fastapi'`/`group = 'fastapi'`.

```bash
sudo adduser fastapi --system --no-create-home --shell /usr/sbin/nologin
```

## Configuration and setup of Nginx (If needed)

In the [nginx.conf_example](/INSTALLATION/nginx.conf_example) be sure to modify the setup to match your environment, and also install a SSL certificate, either through your own or services like Let's Encrypt.

Replace the current "nginx.conf" located at "/etc/nginx/nginx.conf"

## Configuration and setup of Apache (Alternative to Nginx)

If you'd rather use Apache httpd as the reverse proxy, [apache.conf_example](/INSTALLATION/apache.conf_example) provides the same security properties as the nginx config above (TLS termination, security headers, HTTP->HTTPS redirect, and correct reverse-proxy IP header handling). Enable the required modules first:

```bash
sudo a2enmod ssl proxy proxy_http headers rewrite deflate
```

Then adapt the certificate paths and `ServerName` to your environment, same as with the nginx config.

## Configuration and setup of supervisord (Boot type 1)
[Supervisor](http://supervisord.org/introduction.html) is a client/server system that allows its users to monitor and control a number of processes on UNIX-like operating systems.

Modify [uvicorn_start](/INSTALLATION/uvicorn_start) to fit your needs, and copy it to the root directory of the project

```bash
$ cp INSTALLATION/uvicorn_start uvicorn_start.sh

# We want to test that it is working 
$ chmod +x uvicorn_start.sh
$ ./uvicorn_start.sh
```

It should start Cratos FastAPI application using Uvicorn with the predefined settings.

```bash
$ cp INSTALLATION/cratos.conf_example /etc/supervisor/conf.d/cratos.conf
```

Remember to modify the configuration in "cratos.conf" to be adapted to your environment.

Testing and installing the configuration (Also use this if you make changes to the cratos.conf)
```bash
$ sudo supervisorctl reread
$ sudo supervisorctl update
```

And finally test if it starts the Cratos application managed by Supervisor
```bash
sudo supervisorctl start cratos
```

Good command to know with supervisor

```bash 
sudo supervisorctl start cratos
sudo supervisorctl stop cratos 
sudo supervisorctl restart cratos
sudo supervisorctl status cratos

sudo supervisorctl
```

## Configuration and setup of Systemd (Boot type 2) - Recommended

systemd can automatically start Gunicorn when the system boots and restart it if it crashes, ensuring high availability. Additionally systemd provides advanced resource management features, such as CPU and memory limits, which can help prevent Gunicorn from consuming too many resources.

Utilizing systemd also offers security features like sandboxing and process isolation, which can help improve the security of your Gunicorn service.

**Ensure to update INSTALLATION/gunicorn.service_example to fit your installation path**

```bash
cp INSTALLATION/gunicorn.service_example /etc/systemd/system/gunicorn.service
sudo systemctl daemon-reload
sudo systemctl start gunicorn
sudo systemctl enable gunicorn
```

### Gunicorn Configuration

CRATOS FastAPI includes an optimized `gunicorn_config.py` with the following production-ready features:

- **Memory Management**: Workers automatically restart after 250 requests to prevent memory leaks
- **Worker Configuration**: 6 workers by default (adjust based on your server capacity)
- **Proxy Support**: Configured for use behind a reverse proxy (nginx or Apache) running on the same host
- **Logging**: Errors logged to `/var/log/cratos/general.log`, access logs to stdout
- **Port**: Binds to `127.0.0.1:8080` by default — loopback only, reachable only through the reverse proxy on the same host, never directly from the network

**Important Configuration Options in `gunicorn_config.py`:**

```python
workers = 6                    # Number of worker processes
bind = "127.0.0.1:8080"        # IP and port to bind - loopback only, see nginx/apache config
max_requests = 250             # Restart worker after this many requests
max_requests_jitter = 15       # Randomize restart to avoid simultaneous restarts
errorlog = '/var/log/cratos/general.log'  # Error log location
forwarded_allow_ips = '127.0.0.1'  # Only trust forwarded headers from the local reverse proxy - never '*'
proxy_protocol = False          # Disabled - the documented nginx/Apache configs use a standard HTTP
                                 # proxy_pass, which never sends PROXY protocol; only enable this if
                                 # your reverse proxy is explicitly configured to send it
chdir = '/opt/cratos-fastapi'  # Working directory
reload = False                 # Set to True for development auto-reload
```

**Create log directory:**

```bash
sudo mkdir -p /var/log/cratos
sudo chown fastapi:fastapi /var/log/cratos
```

To use the configuration:

```bash
# Using the config file (recommended)
/opt/cratos-fastapi/.venv/bin/gunicorn app.main:app --config /opt/cratos-fastapi/gunicorn_config.py

# Or with command-line options (legacy method) - keep these flags in sync with gunicorn_config.py
/opt/cratos-fastapi/.venv/bin/gunicorn -w 6 -b 127.0.0.1:8080 -k uvicorn.workers.UvicornWorker app.main:app \
  --error-logfile /var/log/cratos/general.log \
  --forwarded-allow-ips '127.0.0.1' \
  --chdir /opt/cratos-fastapi \
  --max-requests 250 \
  --max-requests-jitter 15
```

Or update your systemd service file to reference the config:

```ini
[Service]
User=fastapi
Group=fastapi
WorkingDirectory=/opt/cratos-fastapi
ExecStart=/opt/cratos-fastapi/.venv/bin/gunicorn app.main:app --config /opt/cratos-fastapi/gunicorn_config.py
```

---

# Everything is working

If the Cratos FastAPI is running you should be able to connect to it, and we recommend starting on the help page "https://cratos.yourdomain.com/v1/help"

"https://cratos.yourdomain.com/v1/generate_token_form" to generate your auth token

---

# Contributing
There is always space to contribute to the Cratos FastAPI project.

Feel free to fork the code, play with it, make some patches and send us the pull requests via the issues.

Feel free to contact us, create [issues](https://github.com/eCrimeLabs/cratos-fastapi/issues), if you have questions, remarks or bug reports.

---

# Testing Cratos FastAPI

Running the tests is a way to check that Cratos is working correctly — for example right after installing it, after pulling in an update, or before submitting a code change. You don't need to be a developer to do this; the steps below explain what to type and what the result should look like.

A "test" is a small, automated check built into the project that exercises a piece of the application and confirms it still behaves correctly. They run using a tool called `pytest`, which gets installed automatically when you run `pip install -r requirements.txt` during setup.

First, open a terminal, move into the folder where Cratos FastAPI is installed, and activate its virtual environment:

```bash
cd /opt/cratos-fastapi        # or wherever you installed it
source .venv/bin/activate
```

## Quick checks (start here)

These run entirely on your own machine — no real MISP server, internet connection, or memcached needed. They take only a few seconds and are safe to run any time:

```bash
pytest tests/unit/test_dependencies.py tests/unit/test_auth.py tests/unit/test_feeds.py tests/unit/test_routes_mocked.py
```

A successful run ends with a green-ish summary line like:

```
============================= 115 passed in 16.69s =============================
```

If you see lines starting with `FAILED` instead, see "If a test fails" below.

## Full test against a real MISP instance

This is a more thorough, slower check (a few minutes) that actually connects to a real MISP instance using a genuine Cratos API token, so it also verifies your network connectivity and MISP configuration.

**One-time setup:** copy `test.token.example` to `test.token` and paste a valid Cratos API token into it (see "Configuring your first MISP connection config" above for how to generate one).

```bash
cp test.token.example test.token
```

Then run:

```bash
pytest tests/unit/test_api.py
```

Or, for a report you can open and read in a web browser:

```bash
pytest tests/unit/test_api.py --html=report.html
```

## If a test fails

A `FAILED` line means something isn't behaving as expected. This could be a real bug, a configuration problem (e.g. an expired token, an unreachable MISP server, incorrect file permissions), or something specific to your environment. If you're not sure which, copy the full terminal output and [open an issue](https://github.com/eCrimeLabs/cratos-fastapi/issues), including:
- which command you ran
- the complete output, including the `FAILED` lines
- anything you changed or installed right before it started failing

If you're contributing code, please run at least the quick checks above before committing, to catch problems early.

---

# Software Bill of Materials (SBOM)

`sbom.json` lists every third-party Python package Cratos depends on, with exact versions — useful for vulnerability scanning, license auditing, or any tooling that expects a [CycloneDX](https://cyclonedx.org/) SBOM (e.g. Grype, Dependency-Track, Snyk).

It's generated directly from the locked `requirements.txt`, so it only reflects what's pinned there.

## Checking it's up to date

`sbom.json` only stays accurate if it's regenerated whenever `requirements.txt` changes. To check, regenerate it and see if anything changed:

```bash
source .venv/bin/activate
pip install cyclonedx-bom   # one-time, if not already installed
cyclonedx-py requirements requirements.txt --mc-type application --of JSON -o sbom.json --validate
git diff --stat sbom.json
```

If `git diff` shows changes, commit the regenerated file alongside whatever dependency change caused it.

## Updating dependencies and the SBOM together

Cratos pins exact versions in `requirements.txt`, generated from the looser `requirements.in` via [pip-tools](https://github.com/jazzband/pip-tools). To bump or add a dependency:

```bash
source .venv/bin/activate
pip install pip-tools   # one-time, if not already installed

# 1. Edit requirements.in (add/change the package there, not requirements.txt directly)

# 2. Re-lock requirements.txt
pip-compile requirements.in --output-file=requirements.txt --no-annotate --strip-extras

# 3. Reinstall and run the quick checks (see "Testing Cratos FastAPI" above)
pip install -r requirements.txt
pytest tests/unit/test_dependencies.py tests/unit/test_auth.py tests/unit/test_feeds.py tests/unit/test_routes_mocked.py

# 4. Regenerate the SBOM to match
cyclonedx-py requirements requirements.txt --mc-type application --of JSON -o sbom.json --validate
```

Commit `requirements.in`, `requirements.txt`, and `sbom.json` together so they never drift apart.

## Keeping pymisp current

`pymisp` is the official MISP client library and tends to evolve alongside the MISP server itself, so it's worth checking for updates more often than the rest of the dependencies. To bump just `pymisp` without touching anything else's pinned version:

```bash
source .venv/bin/activate
pip-compile requirements.in --output-file=requirements.txt --upgrade-package pymisp --no-annotate --strip-extras
pip install -r requirements.txt
pytest tests/unit/test_dependencies.py tests/unit/test_auth.py tests/unit/test_feeds.py tests/unit/test_routes_mocked.py
pytest tests/unit/test_api.py   # if you have a test.token configured — exercises real MISP calls through PyMISP
cyclonedx-py requirements requirements.txt --mc-type application --of JSON -o sbom.json --validate
```

---

# License

This software is licensed under [MIT](https://github.com/eCrimeLabs/cratos-fastapi/blob/main/LICENSE)

---

# Todo

- Support of allowing an API key to also get URL's of the MISP instance where a specific indicator exists, this should be done with a boolean when the api token is generated.


---

# Video presentation from Hack.lu 2023
"Cratos - Use your bloody indicators"

https://www.youtube.com/watch?v=yFvvFIq7TKk