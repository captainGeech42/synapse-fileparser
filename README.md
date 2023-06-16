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

# Model changes ([here](/fileparser/pkg/storm/mod_model.storm))

## New Forms

### `_zw:file:mime:pe:import`

```
type: _zw:file:mime:pe:import
base: guid
doc: The fused knowledge of a file:bytes node containing a pe import.
    
file: file:bytes
dll: str
name: str
address: int
ordinal: int
```

### `_zw:file:mime:elf:segment`

Both this form and the corresponding section form are designed similarly to their corresponding Mach-O forms.

```
type: _zw:file:mime:elf:segment
base: guid
doc: A delineated region of bytes inside of an ELF binary.

file: file:bytes
hash: hash:sha256
type: enum
type:raw: int
disksize: int
memsize: int
size: int
```

### `_zw:file:mime:elf:section`

```
type: _zw:file:mime:elf:section
base: guid
doc: A section inside a ELF binary denoting a named region of bytes inside a segment.

segment: _zw:file:mime:elf:segment
hash: hash:sha256
size: int
name: str
offset: int
type: enum
type:raw: int
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

### `file:subfile`

```
// timestamps from archive file formats
// if the container file format doesn't include all three, mtime is used
_archive:mtime
_archive:ctime
_archive:atime
```