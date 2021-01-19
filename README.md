# OneLogin Linux Pam Module Example

This repo implements a simple Linux PAM module and runs a server in a docker container.

## Getting started

1. In your OneLogin account, create two roles: `admin` and `user`

    The `admin` role will have `sudo` permission and the `user` role will not.

2. In your OneLogin account, assign a user (with at least one MFA device), to the `admin` role.

3. From a terminal, create a config file from the template config as shown below:

```
cp docker/src/template-onepam.json docker/src/onepam.json
```

4. From a terminal, set the permissions on the newly created config file to only be readable by the current user as shown below
(this is an added layer to security for the access tokens that will be stored in this file):

```
chmod 600 docker/src/onepam.json
```

5. Edit the newly created configuration file with your favorite editor to enter the `region`, `subdomain`, `client_id`,
`client_secret`, and `user_roles` for your OneLogin account.

   The `client_id` and `client_secret` used need to have `Manage All` permissions.

   Below is an example of the config file filled out with mock values:

```
{
  "region": "us",
  "subdomain": "mysubdomain",
  "client_id": "0000000000000000000000000000000000000000000000000000000000000000",
  "client_secret": "0000000000000000000000000000000000000000000000000000000000000000",
  "request_duration_secs": 1.5,
  "user_roles": {
                  "admin": 000000,
                  "user": 000000
                }
}
```

6. From a terminal, start the docker image with the created configuration file:

```
docker-compose up
```

7. Run the following from a second terminal:

```
ssh admin@127.0.0.1 -p 2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no
```

8. Follow the prompts as shown in the output below:

```
Warning: Permanently added '[127.0.0.1]:2222' (ECDSA) to the list of known hosts.
OneLogin username: oneloginusername
OTP (leave empty if push):
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.39-linuxkit x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

admin@d5e5d3eb9e7a:~$
```

## Files

- `README.md`: Readme...
- `docker-compose.yml`: Compose file...
- `docker/Dockerfile`: Docker file...
- `docker/dependencies`: Dependencies to add into docker container (see section for more details)
- `docker/etc/pam.d/sshd`: SSH pam configuration set to use the PAM module implemented by this repo
- `docker/etc/ssh/sshd_config`: Basic ssh config...
- `docker/src/template-onepam.json`: PAM module python implementation config template
- `docker/src/onepam.json`: PAM module python implementation config (THIS NEEDS TO BE CREATED)
- `docker/src/onepam.py`: PAM module python implementation (does a role based auth check with user+otp)
- `writeup/README.md`: A writeup on the use-case, configuration, and implementation of this module

## Building dependencies

Dependencies have been packaged for ease of deployment to the docker image.

To build them yourself:

    rm -rf dependencies
    pip install -t dependencies onelogin
    rm -rf $(find . -name '*.pyc') $(find . -name __pycache__)

Or to install on a real machine:

    pip install onelogin
