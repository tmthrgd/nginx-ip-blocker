# nginx-ip-blocker

nginx-ip-blocker is the other half of
[tmthrgd/ip-blocker-agent](https://github.com/tmthrgd/ip-blocker-agent).

## Install

```
wget http://nginx.org/download/nginx-1.9.15.tar.gz
tar -xzvf nginx-1.9.15.tar.gz
cd nginx-1.9.15/

# Here we assume Nginx is to be installed under /opt/nginx/.
./configure --prefix=/opt/nginx \
	--add-module=/path/to/nginx-ip-blocker

make -j2
make install
```

## Directives

### ip_blocker

**syntax:** *ip_blocker &lt;name-of-shared-memory&gt; [whitelist code=xxx] | off*

**default:** *ip_blocker off*

**context:** *http, server, server if, location, location if*

Blocks (or whitelists) IP address specified in the named shared memory
(see [tmthrgd/ip-blocker-agent](https://github.com/tmthrgd/ip-blocker-agent)).

The whitelist flag causes matches to be accepted rather than denied.

The code flag allows the HTTP code returned for a match to be specified.

The directive may be specified multiple times to specify multiple blocklists. The exact behaviour depends
on the value of the [satisfy directive](http://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy).

## License

Unless otherwise noted, the nginx-ip-blocker source files are distributed under the Modified BSD License
found in the LICENSE file.
