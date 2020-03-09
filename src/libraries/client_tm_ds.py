import deepsecurity as api
import datetime
from deepsecurity.rest import ApiException as api_exception
from pprint import pprint
import logging
import time
try:
    import src.config as config
except ModuleNotFoundError:
    import config as config
from os import environ

try:
    import src.libraries.ds_search as search
except ModuleNotFoundError:
    import libraries.ds_search as search
import re
# Get the DSM URL and API key from the properties.json file
import json
from datetime import datetime, timedelta


# Logging configuration
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=config.LOG_LEVEL)

# Add the DSM information to the API client configuration
configuration = api.Configuration()  # Create a Configuration object
configuration.host = environ.get(
    "DS_HOST", default=config.DS_HOST)  # Set the URL of the DSM
# Set the secret key for the DSM
configuration.api_key['api-secret-key'] = environ.get(
    "DS_API_KEY", default=config.DS_API_KEY)
configuration.verify_ssl = environ.get(
    "DS_VERIFY_SSL", default=config.DS_VERIFY_SSL)
linux_regex = 'linux|amazon|debian|ubuntu|oracle|centos|red\shat'

# Add the API version to a global variable
api_version = environ.get("DS_API_VERSION", default=config.DS_API_VERSION)

# Add any additional global variables that will be shared across your functions
# Variables for Settings examples
settings_policy_id = 9

template = {
    'vulnerabilities-ips_rules-all-all-all': 0,
    'vulnerabitilies-ips_rules-os_linux-all-all': 0,
    'vulnerabitilies-ips_rules-os_linux-prevent-all': 0,
    'vulnerabitilies-ips_rules-os_linux-prevent-inline': 0,
    'vulnerabitilies-ips_rules-os_linux-prevent-tap': 0,
    'vulnerabitilies-ips_rules-os_linux-detect-all': 0,
    'vulnerabitilies-ips_rules-os_linux-detect-inline': 0,
    'vulnerabitilies-ips_rules-os_linux-detect-tap': 0,
    'vulnerabitilies-ips_rules-os_linux-discovered-all': 0,
    'vulnerabitilies-ips_rules-os_linux-discovered-inline': 0,
    'vulnerabitilies-ips_rules-os_linux-discovered-tap': 0,
    'vulnerabitilies-ips_rules-os_windows-all-all': 0,
    'vulnerabitilies-ips_rules-os_windows-prevent-all': 0,
    'vulnerabitilies-ips_rules-os_windows-prevent-inline': 0,
    'vulnerabitilies-ips_rules-os_windows-prevent-tap': 0,
    'vulnerabitilies-ips_rules-os_windows-detect-all': 0,
    'vulnerabitilies-ips_rules-os_windows-detect-inline': 0,
    'vulnerabitilies-ips_rules-os_windows-detect-tap': 0,
    'vulnerabitilies-ips_rules-os_windows-discovered-all': 0,
    'vulnerabitilies-ips_rules-os_windows-discovered-inline': 0,
    'vulnerabitilies-ips_rules-os_windows-discovered-tap': 0,
    'vulnerabitilies-ips_rules-os_unknown-all-all': 0,
    'vulnerabitilies-ips_rules-os_unknown-prevent-all': 0,
    'vulnerabitilies-ips_rules-os_unknown-prevent-inline': 0,
    'vulnerabitilies-ips_rules-os_unknown-prevent-tap': 0,
    'vulnerabitilies-ips_rules-os_unknown-detect-all': 0,
    'vulnerabitilies-ips_rules-os_unknown-detect-inline': 0,
    'vulnerabitilies-ips_rules-os_unknown-detect-tap': 0,
    'vulnerabitilies-ips_rules-os_unknown-discovered-all': 0,
    'vulnerabitilies-ips_rules-os_unknown-discovered-inline': 0,
    'vulnerabitilies-ips_rules-os_unknown-discovered-tap': 0
}


summary = {
            'timestamp': 0,
            'active': template,
            'warning': template,
            'inactive': template,
            'error': template,
            'unknown': template
            }


def print_dict(var=None, name=None):
    for key, value in var.items():
        print('{} - key: {} - value: {}'.format(name, key, value))


def add_key(key=None, var=None, value=None):
    # "value" is to differentiate when we just add +1 than when we need to add the value (i.e. ips rules)
    if value is None:
        if key in var.keys():
            var[key] += 1
        else:
            var[key] = 1
    else:
        # we are dealing with IPS rules here
        if key in var.keys():
            var[key] += value
        else:
            var[key] = value
    # print('key: {} - value: {}'.format(key, var[key]))



def get_os(var=None):
    if 'windows' in var.lower():
        return 'os_windows'
    elif re.match(linux_regex, var):
        return 'os_linux'
    else:
        return 'os_unknown'


def get_status(var=None, name=None):
    if name is None:
        raise NameError('name variable is Null')
    else:
        if 'on' in var.lower():
            return '{}-on'.format(name)
        else:
            return '{}-off'.format(name)


def check_none_int(item):
    try:
        if item is not None:
            return int(item)
        else:
            return 0
    except Exception:
        return 0


def delta_date(date):
    try:
        now = datetime.now()
        difference = now - date
        seconds_in_day = 24 * 60 * 60
        timedelta(0, 8, 562000)
        delta = divmod(difference.days * seconds_in_day +
                       difference.seconds, 60)
        # (0, 8)      # 0 minutes, 8 seconds
        # print('min: {}'.format(delta[0]))
        # print('sec: {}'.formart(delta[1]))
        return delta[0]
    except Exception as e:
        logging.info('delta_date_error: {}'.format(e))


def get_summary(max_time=60):
    global summary
    try:
        if summary['timestamp'] != 0:
            delta_time = delta_date(summary['timestamp'])
        else:
            summary = ds_summary()
            return summary
        if delta_time >= max_time:
            logging.info('not_valid_delta_date_minutes (> {}): {}'.format(max_time, delta_time))
            summary = ds_summary()
            return summary
        else:
            logging.info(
                'valid_delta_date_minutes (< {}): {}'.format(max_time, delta_time))
            return summary
    except Exception as e:
        logging.info('check_timestamp_error: {}'.format(e))


def ds_summary():
    active = {}
    warning = {}
    inactive = {}
    error = {}
    unknown = {}
    total = 0
    active_total = 0
    ips_status = None
    ips_mode = None

    api_instance = api.ComputersApi(api.ApiClient(configuration))
    overrides = False
    logging.info('ds_summary: calling ds api')
    api_response = api_instance.list_computers(
        api_version, overrides=overrides)


    logging.info('ds_summary: metric calc')
    for computer in api_response.computers:
        try:
            platform = computer.platform.lower()
            agent_status = computer.computer_status.agent_status.lower()
            agent_version_major = int(computer.agent_version.split('.')[0])
            agent_version = computer.agent_version

            am_status = str(
                computer.anti_malware.module_status.agent_status_message).lower()
            wr_status = str(
                computer.web_reputation.module_status.agent_status_message).lower()
            fw_status = str(
                computer.firewall.module_status.agent_status_message).lower()
            ip_status = str(
                computer.intrusion_prevention.module_status.agent_status_message).lower()
            im_status = str(
                computer.integrity_monitoring.module_status.agent_status_message).lower()
            li_status = str(
                computer.log_inspection.module_status.agent_status_message).lower()
            
            os_type = get_os(platform)
            
            total += 1
            
            if computer.intrusion_prevention.module_status.agent_status_message is not None:
                module_agent_status = computer.intrusion_prevention.module_status.agent_status.lower()
                protect_mode = computer.intrusion_prevention.module_status.agent_status_message.lower()
                agent_mode = computer.computer_settings.firewall_setting_network_engine_mode.value.lower()

                if computer.intrusion_prevention.rule_ids is not None:
                    ips_rules = len(computer.intrusion_prevention.rule_ids)
                else:
                    ips_rules = 0
        

                if 'prevent' in protect_mode and not 'inactive' in protect_mode:
                    ips_status = 'prevent'
                elif 'detect' in protect_mode and not 'inactive' in protect_mode:
                    ips_status = 'detect'


                if 'inline' in agent_mode and not 'inactive' in module_agent_status:
                    ips_mode = 'inline'
                elif 'tap' in agent_mode and not 'inactive' in module_agent_status:
                    ips_mode = 'tap'


            if agent_status == 'active':
                active_total += 1

                if 'inactive' in module_agent_status:
                    ips_status = 'discovered'

                add_key(key='computer-platform-all-{}'.format(platform), var=active)
                add_key(key='computer-platform-{}-{}'.format(os_type, platform), var=active)

                add_key(key='computer-os_type-all-all', var=active)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=active)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=active)
   
                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=active)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=active)
                add_key(key='computer-agent_version_major-{}-{}'.format(os_type, agent_version_major), var=active)

                add_key(key=get_status(am_status, 'module-am_status-all'), var=active)
                add_key(key=get_status(wr_status, 'module-wr_status-all'), var=active)
                add_key(key=get_status(fw_status, 'module-fw_status-all'), var=active)
                add_key(key=get_status(ip_status, 'module-ip_status-all'), var=active)
                add_key(key=get_status(im_status, 'module-im_status-all'), var=active)
                add_key(key=get_status(li_status, 'module-li_status-all'), var=active)

                add_key(key=get_status(am_status, 'module-am_status-{}'.format(os_type)), var=active)
                add_key(key=get_status(wr_status, 'module-wr_status-{}'.format(os_type)), var=active)
                add_key(key=get_status(fw_status, 'module-fw_status-{}'.format(os_type)), var=active)
                add_key(key=get_status(ip_status, 'module-ip_status-{}'.format(os_type)), var=active)
                add_key(key=get_status(im_status, 'module-im_status-{}'.format(os_type)), var=active)
                add_key(key=get_status(li_status, 'module-li_status-{}'.format(os_type)), var=active)

                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=active, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                    os_type), var=active, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                    ips_status), var=active, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                    ips_mode), var=active, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=active, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=active, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                    ips_status, ips_mode), var=active, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                    os_type, ips_mode), var=active, value=ips_rules)

            elif agent_status == 'warning':

                if 'inactive' in module_agent_status:
                    ips_status = 'discovered'

                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=warning)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=warning)

                add_key(key='computer-os_type-all-all', var=warning)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=warning)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=warning)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=warning)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=warning)
                add_key(key='computer-agent_version_major-{}-{}'.format(os_type, agent_version_major), var=warning)
   

                add_key(key=get_status(am_status, 'module-am_status-all'), var=warning)
                add_key(key=get_status(wr_status, 'module-wr_status-all'), var=warning)
                add_key(key=get_status(fw_status, 'module-fw_status-all'), var=warning)
                add_key(key=get_status(ip_status, 'module-ip_status-all'), var=warning)
                add_key(key=get_status(im_status, 'module-im_status-all'), var=warning)
                add_key(key=get_status(li_status, 'module-li_status-all'), var=warning)

                add_key(key=get_status(am_status, 'module-am_status-{}'.format(os_type)), var=warning)
                add_key(key=get_status(wr_status, 'module-wr_status-{}'.format(os_type)), var=warning)
                add_key(key=get_status(fw_status, 'module-fw_status-{}'.format(os_type)), var=warning)
                add_key(key=get_status(ip_status, 'module-ip_status-{}'.format(os_type)), var=warning)
                add_key(key=get_status(im_status, 'module-im_status-{}'.format(os_type)), var=warning)
                add_key(key=get_status(li_status, 'module-li_status-{}'.format(os_type)), var=warning)

                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=warning, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                    os_type), var=warning, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                    ips_status), var=warning, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                    ips_mode), var=warning, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=warning, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=warning, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                    ips_status, ips_mode), var=warning, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                    os_type, ips_mode), var=warning, value=ips_rules)
            elif agent_status == 'inactive':


                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=inactive)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=inactive)

                add_key(key='computer-os_type-all-all', var=inactive)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=inactive)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=inactive)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=inactive)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=inactive)
                add_key(key='computer-agent_version_major-{}-{}'.format(os_type, agent_version_major), var=inactive)


                add_key(key=get_status(am_status, 'module-am_status-all'), var=inactive)
                add_key(key=get_status(wr_status, 'module-wr_status-all'), var=inactive)
                add_key(key=get_status(fw_status, 'module-fw_status-all'), var=inactive)
                add_key(key=get_status(ip_status, 'module-ip_status-all'), var=inactive)
                add_key(key=get_status(im_status, 'module-im_status-all'), var=inactive)
                add_key(key=get_status(li_status, 'module-li_status-all'), var=inactive)

                add_key(key=get_status(am_status, 'module-am_status-{}'.format(os_type)), var=inactive)
                add_key(key=get_status(wr_status, 'module-wr_status-{}'.format(os_type)), var=inactive)
                add_key(key=get_status(fw_status, 'module-fw_status-{}'.format(os_type)), var=inactive)
                add_key(key=get_status(ip_status, 'module-ip_status-{}'.format(os_type)), var=inactive)
                add_key(key=get_status(im_status, 'module-im_status-{}'.format(os_type)), var=inactive)
                add_key(key=get_status(li_status, 'module-li_status-{}'.format(os_type)), var=inactive)

                # vulnerabilities-ips_rules-os_windows-prevent-inline - value: 2
                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=inactive, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-{}-all-all'.format(
                    os_type), var=inactive, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-all-{}-all'.format(
                    ips_status), var=inactive, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-all-all-{}'.format(
                    ips_mode), var=inactive, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=inactive, value=ips_rules)
                
                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                    os_type), var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                    ips_status), var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                    ips_mode), var=inactive, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=inactive, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                    ips_status, ips_mode), var=inactive, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                    os_type, ips_mode), var=inactive, value=ips_rules)


            elif agent_status == 'error':
                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=error)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=error)

                add_key(key='computer-os_type-all-all', var=error)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=error)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=error)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=error)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=error)
                add_key(key='computer-agent_version_major-{}-{}'.format(os_type, agent_version_major), var=error)

                add_key(key=get_status(am_status, 'module-am_status-all'), var=error)
                add_key(key=get_status(wr_status, 'module-wr_status-all'), var=error)
                add_key(key=get_status(fw_status, 'module-fw_status-all'), var=error)
                add_key(key=get_status(ip_status, 'module-ip_status-all'), var=error)
                add_key(key=get_status(im_status, 'module-im_status-all'), var=error)
                add_key(key=get_status(li_status, 'module-li_status-all'), var=error)

                add_key(key=get_status(am_status, 'module-am_status-{}'.format(os_type)), var=error)
                add_key(key=get_status(wr_status, 'module-wr_status-{}'.format(os_type)), var=error)
                add_key(key=get_status(fw_status, 'module-fw_status-{}'.format(os_type)), var=error)
                add_key(key=get_status(ip_status, 'module-ip_status-{}'.format(os_type)), var=error)
                add_key(key=get_status(im_status, 'module-im_status-{}'.format(os_type)), var=error)
                add_key(key=get_status(li_status, 'module-li_status-{}'.format(os_type)), var=error)

                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=error, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-{}-all-all'.format(
                    os_type), var=error, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-all-{}-all'.format(
                    ips_status), var=error, value=ips_rules)
                add_key(key='vulnerabitilies-ips_rules-all-all-{}'.format(
                    ips_mode), var=error, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=error, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=error, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                    ips_status, ips_mode), var=error, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                    os_type, ips_mode), var=error, value=ips_rules)
            else:
                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=unknown)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=unknown)

                add_key(key='computer-os_type-all-all', var=unknown)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=unknown)
                add_key(key='computer-os_type-{}-{}'.format(os_type,
                                                            platform), var=unknown)

                add_key(
                    key='computer-agent_version-all-{}'.format(agent_version), var=unknown)
                add_key(key='computer-agent_version-{}-{}'.format(os_type,
                                                                  agent_version), var=unknown)
                add_key(key='computer-agent_version_major-{}-{}'.format(os_type,
                                                                        agent_version_major), var=unknown)

                add_key(key=get_status(am_status, 'module-am_status-all'), var=unknown)
                add_key(key=get_status(wr_status, 'module-wr_status-all'), var=unknown)
                add_key(key=get_status(fw_status, 'module-fw_status-all'), var=unknown)
                add_key(key=get_status(ip_status, 'module-ip_status-all'), var=unknown)
                add_key(key=get_status(im_status, 'module-im_status-all'), var=unknown)
                add_key(key=get_status(li_status, 'module-li_status-all'), var=unknown)

                add_key(key=get_status(am_status, 'module-am_status-{}'.format(os_type)), var=unknown)
                add_key(key=get_status(wr_status, 'module-wr_status-{}'.format(os_type)), var=unknown)
                add_key(key=get_status(fw_status, 'module-fw_status-{}'.format(os_type)), var=unknown)
                add_key(key=get_status(ip_status, 'module-ip_status-{}'.format(os_type)), var=unknown)
                add_key(key=get_status(im_status, 'module-im_status-{}'.format(os_type)), var=unknown)
                add_key(key=get_status(li_status, 'module-li_status-{}'.format(os_type)), var=unknown)

                add_key(key='vulnerabilities-ips_rules-all-all-all',
                        var=unknown, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                    os_type), var=unknown, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                    ips_status), var=unknown, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
                    ips_mode), var=unknown, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-{}-{}-all'.format(
                    os_type, ips_status), var=unknown, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-{}-{}'.format(
                    os_type, ips_status, ips_mode), var=unknown, value=ips_rules)

                add_key(key='vulnerabilities-ips_rules-all-{}-{}'.format(
                    ips_status, ips_mode), var=unknown, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-{}-all-{}'.format(
                    os_type, ips_mode), var=unknown, value=ips_rules)

        except Exception as e:
            logging.info('ds_summary - error: {}'.format(e))

    print_dict(active, 'active')
    print('active hosts: {}'.format(active_total))
    print_dict(inactive, 'inactive')
    print_dict(warning, 'warning')
    print_dict(error, 'error')
    print_dict(unknown, 'unknown')

    # print('total: {}'.format(total))

    summary = { 
                'timestamp': datetime.now(), 
                'active': active,
                'warning': warning, 
                'inactive': inactive, 
                'error': error, 
                'unknown': unknown 
                }
    logging.info('ds_summary: returning metrics')
    return summary

logging.info('starting application: calling get_summary')
summary = get_summary()


def main():
    ''' Run the examples from the Create and Configure Policies guide

    Each function call passes the api client configuration information
    and any required variables and prints their output.
    '''
    # ds_summary()


if __name__ == '__main__':
    main()
