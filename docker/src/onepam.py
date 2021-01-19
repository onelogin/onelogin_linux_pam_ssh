#!/usr/bin/env python2
'''
PAM module for authenticating users via a onelogin email/username and OTP
'''
import json
import os
import sys
import syslog
import time

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

try:
    from onelogin.api.client import OneLoginClient
except Exception as error:
    logit(error)
    raise

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

    # Create a client to OneLogin with the config details
    client = OneLoginClient(config['client_id'], config['client_secret'], config['region'])
    if not client.get_access_token():
        logit('Error authenticating with onelogin')
        return pamh.PAM_AUTH_ERR

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

    # Immediately error on wildcards in email/user from client
    if email_or_user.find('*') >= 0:
        logit('Invalid user "%s"' % email_or_user)
        return pamh.PAM_AUTH_ERR

    # Build uniform request object from config file
    uniform_timer = UniformTimer(config['request_duration_secs'])

    # Make all email/user/checks have a uniform duration (start)
    uniform_timer.start()

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

    # Make all email/user/checks have a uniform duration (finish)
    uniform_timer.finish()

    # Check password (uncomment to add password auth)
    # uniform_timer.start()
    # token = client.create_session_login_token({'username_or_email': email_or_user,
    #                                            'password': password,
    #                                            'subdomain': config['subdomain']})
    # if token is None:
    #     logit('Invalid username or password "%s"' % email_or_user)
    #     user = None
    # uniform_timer.finish()

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

    # Check if user is authorized to login to provided role
    if config['user_roles'].get(rolename, None) not in user.get_role_ids():
        logit('User "%s" is not authorized to login as "%s"' % (email_or_user, rolename))
        return pamh.PAM_AUTH_ERR

    # Auth'd login
    return pamh.PAM_SUCCESS

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
