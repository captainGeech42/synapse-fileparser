# synapse-fileparser
Synapse Advanced Power-up to parse files because I don't have enterprise ;(

# Permissions

This package exposes one permission level:

* `zw.fileparser.user`: Allows use of the fileparser service

# Deployment

## 1. Provision the aha service

```
$ cd /srv/syn/aha
$ docker compose exec aha /bin/bash

# in the AHA container
python -m synapse.tools.aha.provision.service 00.fileparser
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
        - ./storage:/vertex/storage
    environment:
        - SYN_FILEPARSER_AXON=aha://axon...
        - SYN_FILEPARSER_HTTPS_PORT=null
        - SYN_FILEPARSER_AHA_PROVISION=<replaceme>
```

```
$ docker build -t synapse-fileparser .
$ docker compose up
```

## 3. Register the service in your cortex

```
storm> service.add fileparser aha://fileparser...
```

# Model changes ([here](https://github.com/captainGeech42/synapse-fileparser/blob/main/fileparser/consts.py#L18))

## New Forms

### `file:mime:pe:import`

`file:mime:pe:import` is a guid instead of a comp node because an import can be by ordinal or by name. it is up to the node creator to properly disambiguate these outside of the fileparser module.

```
type: file:mime:pe:import
base: guid
doc: The fused knowledge of a file:bytes node containing a pe import.
    
file: file:bytes
dll: str
name: str
address: int
ordinal: int
```

### `file:mime:elf:segment`

```
type: file:mime:elf:segment
base: guid
doc: The fused knowledge of a file:bytes node containing an elf segment.

file: file:bytes
type: enum
type:raw: int
disksize: int
memsize: int
size: int
```

### `file:meme:elf:section`

```
```

## Modified Forms

### `file:mime:pe:export`

```  
_address: int
_ordinal: int
```

### `file:bytes`

```  
// architecture of the executable file
_exe:arch: str

// exphash from pefile
_mime:pe:exphash: hash:sha256
```

### `file:sufile`

```
// timestamps from archive file formats
// if the container file format doesn't include all three, mtime is used
_archive:mtime
_archive:ctime
_archive:atime
```