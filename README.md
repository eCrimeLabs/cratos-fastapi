[<center><img src="cratos_logo.png" width="250"/></center>](logo)


-------------------------------------------

[MISP Threat Sharing Platform](https://misp-project.org/) is an amazing platform for collecting and maintaining your CTI/Incident Response findings and context, but is can also be useful in daily hunting engagements, incident repone cases, standard SecOps and other scenarios; without giving your infrastructure, outsourcing partners access access to context from MISP.

The CRATOS proxy API integrates with one or more MISP instances and allows to extract indicators that can be consumed by security components such as SIEM, DNS, Proxies, Firewalls, EDR, NDR and other that can consume a file with indicators.

Using the CRATOS API it also ensures that indicators are sharable but you will not leak the context or need to give permissions to your MISP instance, and thereby being able to share these indicators in environments where you want to protect your data more. 

# Comon Usecases
The below is just inspiration and you can ingest the data where applicable.

- Ingest data into your protection pipeline
    - Filewall(s) - Active blocking
    - Mail gateway - Active blocking
    - AV product(s) - Active blocking
    - EDR product(s) - Active blocking or Passive detection
    - Proxy product(s) - Active blocking
    - SIEM solution(s) - Passive detection
- Provide a feed to your vulnerability team


# How do I get set up?

The below guide has been tested and validated on Debian and Ubuntu, it is recommended to create a virtual environment

## Debian / Ubuntu

We recommend to git clone the Cratos FastAPI into the system to more easily be able to update when updates arrive.

```bash 
$ sudo apt install git 
$ cd /opt
$ git clone https://github.com/eCrimeLabs/cratos-fastapi.git
```

## Cratos FastAPI Configurable Files

We will start here as the dependencies to the code running will be used later.

| filename/folder      | Description |
| -------------------- | ------------------------------------------------------------------- |
| log_conf.yaml        | This is the logging configuration file for uvicorn                  |
| config/config.yaml   | Contains the core configurations                                    |
| sites/\<fqdn\>.yaml  | This contains the configuration files related to each MISP instance |

### config/config.yaml ####

Here is a oneliner that can be used to to create an encryption key

```
openssl rand -base64 4096 | sha256sum | tr '[:lower:]' '[:upper:]'
```

Copy the SHA256 string into the "encryption_key" field.

for the "salt" it will be similar:
```
< /dev/urandom tr -dc 'A-Za-z0-9!#?' | head -c 32; echo
```

Now update the "config/config.yaml and save.
```yaml
---

debug: False
encryption_key: "<GENERATE ME>"
salt: "<GENERATE ME>"
memcached_user: ""
memcached_pass: ""
memcached_host: "127.0.0.1"
memcached_port: "11211"
allways_allowed_ips:
  - "100.64.3.0/24"
  - "10.0.0.0/8"
  - "172.16.0.0/12"
  - "192.168.0.0/16"

```

***NOTICE: The "allways_allowed_ips" is globally set for all sites, these will typically be your monitoring setup to ensure that the service is running, the site specific if defined further down.***

## Configuring your first MISP connection config

In the folder sites you generate a file with the name "\<FQDN\>.yaml" this can also be "\<IP\>.yaml" but it has to map the MISP instance, as it is used as one of the validators if Cratos FastAPI is allowed to connect to this instance and how.

The configuraiton files is located in the folder "sites"

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

The field from the "tag" combined with som build-in feeds and 5 custom feeds will be mapped towards the tagging system, so with this setup you will have to following tags that map to these overall feed groups.

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
This is "Optional" in the event that you are using an allready existing memcached sever or cluster

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


## Creating and installing Cratos python dependencies

```bash
$ python3 -m venv .venv
$ .venv/bin/pip install -r requirements.txt
```

## Configuraiton and setup of Nginx

In the [nginx.conf](/INSTALLATION/nginx.conf) be sure to modify the setup to match your environment, and also install a SSL certificate, either through your own or services like Let's Encrypt.

Replace the current "nginx.conf" located at "/etc/nginx/nginx.conf"

## Configuration and setup of supervisord 
[Supervisor](http://supervisord.org/introduction.html) is a client/server system that allows its users to monitor and control a number of processes on UNIX-like operating systems.

Modify [uvicorn_start](/INSTALLATION/uvicorn_start) to fit your needs, and copy it to the root directory of the project

```bash
$ cp INSTALLATION/uvicorn_start uvicorn_start.sh

# (OPTIONAL) If logging is enabled in the uvicorn_start.sh 
$ cp INSTALLATION/log_conf.yaml log_conf.yaml

# We want to test that it is working 
$ chmod +x uvicorn_start.sh
$ ./uvicorn_start.sh
```

It should start Cratos FastAPI application using Uvicorn with the predefined settings.

```bash
$ cp INSTALLATION/cratos.conf /etc/supervisor/conf.d/cratos.conf
```

Remember to modify the configuraiton in "cratos.conf" to be adapted to your environment.

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

# Everything is working

If the Cratos FastAPI is running you should be able to connect to is and we recommend starting on the help page "https://cratos.yourdomain.com/v1/help"

"https://cratos.yourdomain.com/v1/generate_token_form" to generate your auth token

# Contributing
There is allways space to contribute to the Cratos FastAPI project.

Feel free to fork the code, play with it, make some patches and send us the pull requests via the issues.

Feel free to contact us, create [issues](https://github.com/eCrimeLabs/cratos-fastapi/issues), if you have questions, remarks or bug reports.

# Unit testing 
If commiting code to this project please ensure to run a unit test prior, to identify potential errors 

*Standard Test*

```
pytest tests/unit/test_api.py
```

*Standard Test with HTML report*
```
pytest tests/unit/test_api.py --html=report.html
```
# License

This software is licensed under [MIT](https://github.com/eCrimeLabs/cratos-fastapi/blob/main/LICENSE)

# Todo

- Support of allowing an API key to also get URL's of the MISP instance where a specific indicator exists, this should be done with a boolean when the api token is generated.
- Implement logging within the Cratos, to replace the current Uvicorn logging.


# Video presentation from Hack.lu 2023
"Cratos - Use your bloody indicators"

https://www.youtube.com/watch?v=yFvvFIq7TKk