# Writeup

## Introduction

The author of this writeup is by no means a PAM expert.
Please do your due diligence and have any configurations/code written using this guide go through a security check
BEFORE putting it into production.

This guide will walk through the development of implementing an SSH PAM module.

PAM, in this context, stands for Pluggable Authentication Modules (so we say pluggable authentication modules module :joy:).

By implementing a module, we can add custom authentication methods for users.

In this writeup, we're going to be writing a Linux PAM module to authenticate users via OneLogin.

## Is PAM for me?

Let's start with why you might want a PAM module like this.

Let's say you're a system administrator, and have users that need to ssh into multiple servers with
varying user permissions.

Maybe you have some users that need to be able to ssh in and do things as root (such as to restart a service) and other users that
need to ssh in to only view logs (no root powers needed).

The most basic approach is to setup a user account + password on each server. This obviously isn't very easy to manage:

- Adding a new employee would require adding a new account to X servers
- Removing a non-active employee would require removing an account from X servers
- Modifying permissions for an employee would require modifying an account on X servers
- Ensuring passwords are updated and matching on each server also means repeating this action on X servers

Another basic option is to maintain a list of ssh keys and a list of user accounts that are more like roles (ex: admin, user, etc...).
This option is a little easier to manage permissions, as a user's permission is linked to a single account, but still requires
maintaining several servers individually.

There are many solutions to this problem, but one easy to setup option is by using a PAM module to authenticate users via OneLogin.

In this example, we'll be treating server user accounts as OneLogin roles, and using these Roles to manage OneLogin user permissions to
these servers. This will enable system administrators to:

- Setup a PAM configuration once on each server
- Maintain user permissions in a centralized location
- Apply password requirements in a centralized location
- Require two factor/OTP
- `!!(DOUBLE CHECK THIS)!!` Log server accesses (both failed and successful) with date and location information in a centralized location

## Setup

In this guide we'll have the following two roles:

- server1-admin (OneLogin users with this role will have sudo privileges on server1)
- server1-user (OneLogin users with this role will have non-sudo privileges on server1)

### Api Credentials
We need to create a set of api credentials to enable the ability to make api calls.

If you haven't already, create/login to your OneLogin account with an administrator account and select `Administration` on the top right:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/0_credentials/0.png)

From the Administration page, select `API Credentials` from the `Developers` dropdown menu located on the top menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/0_credentials/1.png)

Select the `New Credential` button located just under the top menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/0_credentials/2.png)

Select a name for your credential (such as `Server1 SSH` - I'm going to use `manage_all`
because I have no imagination) and set the credential type to `Manage All`:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/0_credentials/3.png)

Select `Save`, and take note of the `Client ID` and `Client Secret` (we will need these later):

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/0_credentials/4.png)

### Creating and Configuring Roles

Now let's create the `server1-admin` and `server1-user` roles.

Select `Roles` from the `Users` dropdown menu located on the top menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/0.png)

Select the `New Role` button located just under the top menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/1.png)

Enter the new role name `server1-admin`, select the `green checkmark`, and select `Save`:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/2.png)

Now that you've created a role, let's add a user to it.

Select the newly created role from the roles page:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/3.png)

Take note of the `role id` - this is located in the address bar (mine in this case is `393427`):

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/4.png)

We will need this role id to link to a Linux user (in my case, the `admin` user on my Linux
server will be linked to `393427`).

Select `Users` from the left side menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/5.png)

Enter the name of a user you'd like to use to login. I'll be using a non-administrator user I've created named `mittens`.

Afterwards, select `Check`:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/6.png)

Select the `Add To Role` link to the right of the user entry:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/7.png)

Select `Save`:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/8.png)

Note: Changes will not take place unless you Select `Save`!

Now that you've created the `server1-admin` role - follow the same steps to create a `server1-user` role.

At the end, you should have two new roles (in addition to the `Default` role):

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/1_roles/9.png)

### Users

Login as the OneLogin user that you're going to use to login to the ssh server.

Select `Profile` from the user dropdown menu located on the top menu bar:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/2_users/0.png)

Select `Security Factors` from the left side menu and add at least one OTP security factor:

![](https://github.com/onelogin/onelogin_linux_pam_ssh/raw/master/writeup/img/2_users/1.png)

### Server configuration

Let's start by installing the dependencies for onepam (these are for `apt`, the names of packages may vary on other distributions):

    sudo apt update
    sudo apt install -y libpam-python

If your server doesn't have ssh installed, install it (again, this is for `apt`, the names of packages may vary on other distributions):

    sudo apt install -y openssh-server

Next, we'll install the python dependencies:

    pip install onelogin

You may need to make a couple directories depending on your distribution (this won't hurt anything if they already exist):

    mkdir -p /lib/security /run/sshd /opt/onepam

We need to make our Linux side users (aka, the OneLogin roles):

    useradd -rm -d /home/admin -s /bin/bash -G sudo admin
    useradd -rm -d /home/user -s /bin/bash user

Optionally, if you'd like the `admin` user to be able to sudo without a password:

    echo 'admin ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

Copy `onepam.py` to `/opt/onepam/onepam.py` and `template-onepam.json` to `/opt/onepam/onepam.json`.

For added security, change the permissions of the contents of `/opt/onepam` to be owned by `root`:

    chown -R root:root /opt/onepam

Also change the permissions of the `onepam.json` to only be read/written by its owner:

    chmod 600 /opt/onepam/onepam.json

And finally change the permissions of the `onepam.py` to only be executed/read/written by its owner:

    chmod 700 /opt/onepam/onepam.py

Now edit `/opt/onepam/onepam.json` and enter the details we noted from before.

Below is my config:

    {
      "region": "us",
      "subdomain": "scratchpost",
      "client_id": "0000000000000000000000000000000000000000000000000000000000000000",
      "client_secret": "0000000000000000000000000000000000000000000000000000000000000000",
      "request_duration_secs": 1.5,
      "user_roles": {
                      "admin": 393427,
                      "user": 393428
                    }
    }

A note on the `user_roles` - we have two Linux side users: `admin` and `user`, these are what you will
use to login to your machine. Example (don't run yet!):

    ssh admin@server1-hostname
    ssh admin@server1-ipaddress

Open `/etc/ssh/sshd_config` with your favorite editor and make sure it has the following lines in it:

    UsePAM yes
    ChallengeResponseAuthentication yes
    PasswordAuthentication no

Note: The `PasswordAuthentication no` setting isn't technically needed, as we will be overriding all
ssh `password` based authentication. If it is set to yes, `password` based auth sessions will prompt
for a password, but all attempts will fail. If we set this setting to no, the server will reject
`password` based auth entirely, and will only accept `publickey` and `keyboard-interactive` auth
attempts (assuming the server doesn't have other custom methods defined).

Open `/etc/pam.d/sshd` with your favorite text editor and change:

    @include common-auth

To:

    # @include common-auth
    auth required pam_python.so /opt/onepam/onepam.py

And change:

    @include common-account

To:

    # @include common-account
    account required pam_python.so /opt/onepam/onepam.py

Note: The above will disable password based ssh authentication for ALL users on the server.
Key based auth will still function as expected (and will be preferred if there is a key defined for
a given unix user).

Now restart `ssh` for these changes to be applied:

    sudo systemctl restart ssh

At this point, assuming the setup above was followed correctly, you are able to ssh into the server with your OneLogin credentials:

    Warning: Permanently added '[server1]:22' (ECDSA) to the list of known hosts.
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

    admin@server1:~$

## The Module

In this section, we'll take a look at the module implementation and run through the development
mindset of why it was implemented as it is.

The line below might be a little scary:

    #!/usr/bin/env python2

The most up to date version of libpam-python only has python2.7 support. The module is very close
to having python3 support if the conversation linked below is any indication:

https://sourceforge.net/p/pam-python/tickets/5/

This module is python3 compliant, so the upgrade to libpam-python3 shouldn't* require any changes to
the implementation of this module :smiley:

Next we have some very basic imports:

    '''
    PAM module for authenticating users via a onelogin email/username and OTP
    '''
    import json
    import os
    import sys
    import syslog
    import time

There isn't any default logging...we should log...log data will be sent to stderr (visible via docker)
and syslog (docker + not docker):

    def logit(data):
        '''
        Logs data to stderr and syslog
        Args:
            data (*): Data to log
        Returns: None
        '''
        data_str = str(data)
        sys.stderr.write('%s\n' % data_str)
        syslog.syslog(syslog.LOG_ERR, data_str)

Next is a non-standard module import (the onelogin python sdk):

    try:
        from onelogin.api.client import OneLoginClient
    except Exception as error:
        logit(error)
        raise

It's wrapped so we can see an import error in the event it isn't installed.

Moving on, we have a uniform timer class. This mitigates user enumeration/timing attacks by ensuring
all requests last throughout a specified time period. This is configurable by the
`request_duration_secs` option in `onelogin.json`.

    class UniformTimer:
        '''
        This class is used to make sections of code run in a uniform time.
        '''
        def __init__(self, base_duration_secs):
            '''
            Constructor (doesn't start timing)
            Args:
                base_duration_secs (float): Default timer value
            '''
            self.base_duration_secs = base_duration_secs
            self.timer = 0

        def start(self, duration_secs=None):
            '''
            Start timer (non-blocking)
            Args:
                duration_secs (float|None): Override the default timer value
                                            with this value (optional).
            '''
            if duration_secs is None:
                duration_secs = self.base_duration_secs
            self.timer = time.time() + duration_secs

        def finish(self):
            '''
            Waits for timer to expire (blocking)
            Args:
                None
            '''
            time.sleep(max(0, self.timer - time.time()))

Now we'll skip over the `pam_sm_authenticate` method and go down to the placeholder
methods at the end of the file:

    def pam_sm_setcred(pamh, _flags, _argv):
        '''
        Default
        '''
        return pamh.PAM_SUCCESS

    def pam_sm_acct_mgmt(pamh, _flags, _argv):
        '''
        Default
        '''
        return pamh.PAM_SUCCESS

    def pam_sm_open_session(pamh, _flags, _argv):
        '''
        Default
        '''
        return pamh.PAM_SUCCESS

    def pam_sm_close_session(pamh, _flags, _argv):
        '''
        Default
        '''
        return pamh.PAM_SUCCESS

    def pam_sm_chauthtok(pamh, _flags, _argv):
        '''
        Default
        '''
        return pamh.PAM_SUCCESS

The methods above need to be defined, but our authentication doesn't change any of these flows. We
are simply returning the defaults.

Now onto the main chunk of this module - the `pam_sm_authenticate` method:

    def pam_sm_authenticate(pamh, _flags, _argv):
        '''
        Authenticates a user via onelogin email/username and OTP
        '''
        # Load config file and build access token
        try:
            config_dpath = os.path.dirname(os.path.realpath(__file__))
            config_fpath = os.path.join(config_dpath, 'onepam.json')
            config_fd = open(config_fpath, 'r')
            config = config_fd.read()
            config_fd.close()
            config = json.loads(config)
        except Exception as error:
            logit('Error loading configuration: %s' % error)
            return pamh.PAM_AUTH_ERR

The first portion above loads the JSON config file (located in the same folder as the `onepam.py` file).

Once the config is loaded, we make a OneLogin client connection with the supplied config:

        # Create a client to OneLogin with the config details
        client = OneLoginClient(config['client_id'], config['client_secret'], config['region'])
        if not client.get_access_token():
            logit('Error authenticating with onelogin')
            return pamh.PAM_AUTH_ERR

Next, we prompt the user for either the unix user (the OneLogin role name in our case) if needed,
and the email/username of the OneLogin user we're authenticating (uncomment the password section
if you'd like to require a user/email+password+otp):

        # Prompt user for needed information
        try:
            # Unix user (aka, the onelogin role - usually passed via ssh, but may need to prompt)
            rolename = pamh.get_user(None)
            if rolename is None:
                return pamh.PAM_USER_UNKNOWN

            # OneLogin email/user
            email_or_user = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_ON,
                                                           'OneLogin email or user: ')).resp

            # OneLogin password (uncomment to add password auth)
            # password = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,
            #                                           'OneLogin password: ')).resp
        except pamh.exception as error:
            return error.pam_result

One downfall of asking for just a OneLogin email/username is that the api endpoint supports wildcards.
We only want to look for a single user, so we're just going to error on any encountered wildcard
characters:

        # Immediately error on wildcards in email/user from client
        if email_or_user.find('*') >= 0:
            logit('Invalid user "%s"' % email_or_user)
            return pamh.PAM_AUTH_ERR

Now we'll create a uniform timer object that we'll use when making requests:

    # Build uniform request object from config file
    uniform_timer = UniformTimer(config['request_duration_secs'])

And we'll start the timer:

    # Make all email/user/checks have a uniform duration (start)
    uniform_timer.start()

Since we don't know if the supplied string is an email or a username, we need to query both:

        # Query emails
        emails = client.get_users({'email': email_or_user})
        if emails is None:
            logit('Error querying email "%s"' % email_or_user)
            return pamh.PAM_AUTH_ERR

        # Query users
        users = client.get_users({'username': email_or_user})
        if users is None:
            logit('Error querying user "%s"' % email_or_user)
            return pamh.PAM_AUTH_ERR

Now we'll select the first email/username we encounter (in that order):

        # Search emails first then users
        user = None
        for entry in emails:
            if entry.email == email_or_user:
                user = entry
                break
        if not user:
            for entry in users:
                if entry.username == email_or_user:
                    user = entry
                    break

And we'll finish by running out the time block:

    # Make all email/user/checks have a uniform duration (finish)
    uniform_timer.finish()

At this point, some might ask "Why not request and check emails, then request and check the username?
That would lower the number of network connections!"

While the above is true, one thing this module attempts to mitigate is user enumeration. It makes the
attacker's job much harder if they don't know which user they need to brute force a password for.
Always making both requests means there is no difference in timing between a correct email vs a
correct username, making it harder to enumerate possible accounts to try passwords for.

Optionally, we also verify a user's password:

    # Check password (uncomment to add password auth)
    # uniform_timer.start()
    # token = client.create_session_login_token({'username_or_email': email_or_user,
    #                                            'password': password,
    #                                            'subdomain': config['subdomain']})
    # if token is None:
    #     logit('Invalid username or password "%s"' % email_or_user)
    #     user = None
    # uniform_timer.finish()

Why is the password prompt commented out? The writer of this module thinks the OneLogin password should
never be used outside of OneLogin interfaces. While accepting passwords isn't in itself a vulnerability,
the interface could be leveraged by an attacker post-exploitation. The writer thinks Username/Email+OTP
is secure enough for most use-cases, but only you, the administrator, can make this decision.

Next, we lookup OTP factors for a user:

        # Valid user - query otp factors
        uniform_timer.start()
        device = None
        if user:
            factors = client.get_enrolled_factors(user.id)

            # Error querying devices - log and set user to None
            if factors is None:
                logit('Error querying enrolled factors for user "%s"' % email_or_user)
                user = None

            # Find a factor for user (default is preferred, will use first listed otherwise)
            else:
                for factor in factors:
                    # Only care about usable factors
                    if not factor.active:
                        continue

                    # Device is the default device - set and break
                    if factor.default:
                        device = factor
                        break

                    # Device isn't default, but some device is better than no device
                    if device is None:
                        device = factor
        else:
            logit('Invalid email/user "%s"' % email_or_user)
        uniform_timer.finish()

Assuming the user has a valid OTP factor, we active it, and then prompt regardless if it existed or
not:

        # User has a valid otp factor - activate it
        uniform_timer.start()
        state_token = None
        if user is not None and device is not None:
            # Grab state token
            state_token = device.state_token

            # Only trigger if device needs it
            if device.needs_trigger:
                activation = client.activate_factor(user.id, device.id)
                if not activation:
                    logit('Error activating factor id %d for user "%s"' % (device.id, email_or_user))
                else:
                    state_token = activation.state_token

        # No active/default factor - log and set user to None
        else:
            logit('No valid otp factor found for user "%s"' % email_or_user)
        uniform_timer.finish()

        # Prompt for otp
        try:
            otp_token = pamh.conversation(pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, 'OTP: ')).resp
            if not otp_token:
                otp_token = None
        except pamh.exception as error:
            return error.pam_result


Again, why prompt regardless of whether it was found or not? User enumeration mitigation (probably
tired of reading this by now :joy:).

Next we verify the OTP:

        # Verify otp
        uniform_timer.start()
        result = False
        if user is not None and device is not None:
            result = client.verify_factor(user.id,
                                          device.id,
                                          otp_token=otp_token,
                                          state_token=state_token)
        uniform_timer.finish()

        # Error verifying otp - log
        if result is None:
            logit('Error verifying factor id %d for user "%s"' % (device.id, email_or_user))
            return pamh.PAM_AUTH_ERR

        # Invalid otp - log
        if not result:
            logit('Invalid otp auth for user "%s"' % email_or_user)
            return pamh.PAM_AUTH_ERR

At this point, we just need to check that the role is correct. We already have the roles for the user,
so we just need to check that it's in their list of roles:

        # Check if user is authorized to login to provided role
        if config['user_roles'].get(rolename, None) not in user.get_role_ids():
            logit('User "%s" is not authorized to login as "%s"' % (email_or_user, rolename))
            return pamh.PAM_AUTH_ERR

        # Auth'd login
        return pamh.PAM_SUCCESS

That's it! That's the whole module.

## Closing Notes

In this writeup we’ve introduced what a PAM module is and how it can be useful for system administrators.

We ran through the setup on OneLogin and a Linux server.

Finally, we went over the module itself, the known issues with it, and why it is implemented the way it is.
