# Initscripts
These initscripts can be used to integrate one or several sanctum tunnels
with your service manager. Currently there are initscripts offered for
OpenRC and systemd.

For both OpenRC and systemd, the tunnel name that is chosen will be used
to find an appropriate configuration in the configuration directory that
is configured:

* /etc/sanctum (openrc)
* /etc/sanctum for sanctum@ target (systemd)
* /etc/hymn for the sanctum-hymn@ target (systemd)

## OpenRC

In the openrc directory, there are two files, sanctum.confd and sanctum.initd.

```
# cp share/initscripts/openrc/sanctum.confd /etc/conf.d/sanctum
# cp share/initscripts/openrc/sanctum.initd /etc/init.d/sanctum
```

The way the initscript is structured is that you symlink your actual tunnels
to the /etc/init.d/sanctum service for example:

```
# ln -s /etc/init.d/sanctum /etc/init.d/sanctum.manual-setup
```

Then you either set tunnel specific options in **/etc/conf.d/sanctum.<tunnel>**
(for the tunnel in the example above, you'd make a file called
/etc/conf.d/sanctum.manual-setup) or rely on the defaults provided
in /etc/conf.d/sanctum.

## Systemd

In the systemd directory there are two service files, one for manual tunnels
and one for hymn managed tunnels. Install both of these in the correct place:

```
# cp share/initscripts/systemd/* /usr/lib/systemd/system
# systemctl daemon-reload
```

The sanctum@.service file is for manually setup sanctum tunnels,
it has an environment variable set in the service file that can be
overriden by executing

```
$ systemctl edit sanctum@<tunnel name>
```

and writing your own [Unit] section like this:

```
[Unit]
Environment=CONF_DIR=/path/to/foo
```

The sanctum-hymn@.service file is for tunnels that are created and
managed by the hymn tool. It uses the hymn tool to start, stop and
restart the tunnels instead of directly invoking the sanctum binary.

The way they are used is by starting/enabling a service with a tunnel
name like

```
# systemctl start sanctum-manual@test
```

for manual tunnels, or for ones managed via hymn:

```
# systemctl start sanctum-hymn@hymn-01-02
```

If you are using the sanctum-hymn@.service for starting liturgy
tunnels you must set HYMN_USER in the environment so hymn can
pickup the indented user to configure things as:

```
# systemctl edit sanctum-hymn@hymn-01-02
```

```
[Service]
Environment="HYMN_USER=username"
```
