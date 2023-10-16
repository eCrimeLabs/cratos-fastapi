[<center><img src="cratos_logo.png" width="250"/></center>](logo)

<b><p style="text-align: center;">FastAPI proxy integration for MISP</p></b>
-------------------------------------------

The CRATOS proxy API integrates with your MISP instance and allows to extract indicators that can be consumed by security components such as SIEM, DNS, Proxies, Firewalls, EDR, NDR and other that can consume a file with indicators.

With the CRATOS API it also ensures that indicators are sharable but you will not leak the context or need to give permissions to your MISP instance, and thereby being able to share these indicators in environments where you want to protect your data more. 

### How do I get set up? ###

The below guide has been tested and validated on Debian and Ubuntu, it is recommended to create a virtual environment

#### Debian / Ubuntu ####
apt-get install gcc openssl libssl-dev python-dev
python -m pip3 install -r requirements.txt

./venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 --proxy-headers --reload --log-config=log_conf.yaml --proxy-headers 

### TODO ###

- Support of allowing an API key to also get URL's of the MISP instance where a specific indicator exists, this should be done with a boolean when the api token is generated.
- Implement logging within the Cratos, to replace the current Uvicorn logging.



## Configurable Files ##

| filename/folder      | Description |
| -------------------- | ------------------------------------------------------------------- |
| log_conf.yaml        | This is the logging configuration file for uvicorn                  |
| config/config.json   | Contains the core configurations                                    |
| config/mappings.json | Contains mappings for data and time                                 |
| sites/<fqdn>.json    | This contains the configuration files related to each MISP instance |



