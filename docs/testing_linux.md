# Test setup on Linux

The **test* directory contains configuration files and helpful scripts
to test several features of sanctum on Linux.

In order to run these you have to first configure your Linux environment.

All test setups work in a left-right fashion. We will create two network
namespaces for these:

```
# ip add netns add left
# ip add netns add right
```

Now you can run the setup script:

```
$ sudo ./test/linux-setup.sh
```

This will setup and move interfaces into the correct namespaces and create
a bridge interface connecting the both.

```
                      +---------------+
                      [ crypto-bridge ]
                      +---------------+
                      |               |
    left-link <-------+               +-------> right-link
        v                                           v
        v                                           v
  cry.left (left ns)                        cry.right (right ns)
```

After this setup is completed you can use the **test/linux-left.sh**
and **test/linux-right.sh** scripts to start a sanctum instance in
either the left or right namespace.

For example to run the standard tunnel setup you start both the
left and the right side in two separate terminals:

```
$ sudo ./test/linux-left.sh test/left.conf
```

```
$ sudo ./test/linux-right.sh test/right.conf
```

You can use the **test/linux-teardown.sh** script to reset the
network configuration that was previously done.
