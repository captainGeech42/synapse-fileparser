# synapse-fileparser
Synapse Advanced Power-up to parse files because I don't have enterprise ;(

# Deployment

## 1. Provision the aha service

```
$ cd /srv/syn/aha
$ docker compose exec aha /bin/bash

# in the AHA container
python -m synapse.tools.aha.provision.service 00.test
one-time use URL: ssl://aha..............
```

## 2. Start the service

Create a `docker-compose.yml` file:

```yaml
version: "3.3"
services:
  00.test:
    user: "999"
    image: synapse-fileparser
    network_mode: host
    restart: unless-stopped
    volumes:
        - ../testdir:/vertex/storage
    environment:
        - SYN_EXAMPLE_HTTPS_PORT=null
        - SYN_EXAMPLE_AHA_PROVISION=ssl://aha..................................
```

```
$ docker build -t synapse-fileparser .
$ docker compose up
```

## 3. Register the service in your cortex

```
storm> service.add test aha://00.test................
```