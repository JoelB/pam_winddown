# pam_winddown
`pam_winddown` is a [Linux PAM module](https://en.wikipedia.org/wiki/Linux_PAM) that prevents users from logging in to new sessions on a server while still allowing existing sessions to continue. This allows a system administrator to gracefully bring a server down to maintenance without kicking off active users. 

## Warning

This is my first PAM module, and is largely based off of the pam_slurm module.
While it theoretically shouldn't create any security holes that didn't already 
exist (e.g. if you PAM modules are configured correctly), it is provided with 
absolutely no warranty and is recommended not to be used on any systems that
require high security.

## Compiling

To compile, simply run `make && sudo make install`.

`pam_winddown` has only been tested on Ubuntu 16.04 but should work on other
Linux systems. You make need to edit the `PAM_MODULE_PATH` in the Makefile.

On Debian-based systems, you will need to install the PAM development headers by
running `apt install libpam0g-dev`.

## How to use

To use this module, you'll first need to add it into your PAM config files. 

For example, to prevent SSH logins, you can edit `/etc/pam.d/sshd` and add the
following lines:

```
# Allow local users (e.g. localadmin) to bypass wind-down restrictions
account    sufficient   pam_localuser.so

# Disallow new sessions if /etc/winddown exists
account    required   pam_winddown.so
```

If you want to wind-down the system, simply create the file `/etc/winddown`:

```touch /etc/winddown```

When a user attempts to login to the system who does not have any active
processes, they will receive the following error:

```
Access denied: user jsmith (uid=12345) does not have an active session and this node is in wind-down mode (going offline for maintenance).
Connection to my_host closed by remote host.
Connection to my_host closed.
```

## Contributing

I'm open to any and all contributions. This was just a small project to scratch
an itch so hopefully it can scratch yours too :)


