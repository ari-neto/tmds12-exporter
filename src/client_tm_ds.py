import deepsecurity as api
import datetime
from deepsecurity.rest import ApiException as api_exception
from pprint import pprint
import logging
import time
import config
from os import environ
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
page_size = environ.get(
    "PAGE_SIZE", default=config.DS_PAGE_SIZE)
linux_regex = 'linux|amazon|debian|ubuntu|oracle|centos|red\shat'

# Add the API version to a global variable
api_version = environ.get("DS_API_VERSION", default=config.DS_API_VERSION)

# Add any additional global variables that will be shared across your functions
# Variables for Settings examples
settings_policy_id = 9

# possible bug
# template = {
#     'vulnerabilities-ips_rules-all-all-all': 0,
#     'vulnerabitilies-ips_rules-os_linux-all-all': 0,
#     'vulnerabitilies-ips_rules-os_linux-prevent-all': 0,
#     'vulnerabitilies-ips_rules-os_linux-prevent-inline': 0,
#     'vulnerabitilies-ips_rules-os_linux-prevent-tap': 0,
#     'vulnerabitilies-ips_rules-os_linux-detect-all': 0,
#     'vulnerabitilies-ips_rules-os_linux-detect-inline': 0,
#     'vulnerabitilies-ips_rules-os_linux-detect-tap': 0,
#     'vulnerabitilies-ips_rules-os_linux-discovered-all': 0,
#     'vulnerabitilies-ips_rules-os_linux-discovered-inline': 0,
#     'vulnerabitilies-ips_rules-os_linux-discovered-tap': 0,
#     'vulnerabitilies-ips_rules-os_windows-all-all': 0,
#     'vulnerabitilies-ips_rules-os_windows-prevent-all': 0,
#     'vulnerabitilies-ips_rules-os_windows-prevent-inline': 0,
#     'vulnerabitilies-ips_rules-os_windows-prevent-tap': 0,
#     'vulnerabitilies-ips_rules-os_windows-detect-all': 0,
#     'vulnerabitilies-ips_rules-os_windows-detect-inline': 0,
#     'vulnerabitilies-ips_rules-os_windows-detect-tap': 0,
#     'vulnerabitilies-ips_rules-os_windows-discovered-all': 0,
#     'vulnerabitilies-ips_rules-os_windows-discovered-inline': 0,
#     'vulnerabitilies-ips_rules-os_windows-discovered-tap': 0,
#     'vulnerabitilies-ips_rules-os_unknown-all-all': 0,
#     'vulnerabitilies-ips_rules-os_unknown-prevent-all': 0,
#     'vulnerabitilies-ips_rules-os_unknown-prevent-inline': 0,
#     'vulnerabitilies-ips_rules-os_unknown-prevent-tap': 0,
#     'vulnerabitilies-ips_rules-os_unknown-detect-all': 0,
#     'vulnerabitilies-ips_rules-os_unknown-detect-inline': 0,
#     'vulnerabitilies-ips_rules-os_unknown-detect-tap': 0,
#     'vulnerabitilies-ips_rules-os_unknown-discovered-all': 0,
#     'vulnerabitilies-ips_rules-os_unknown-discovered-inline': 0,
#     'vulnerabitilies-ips_rules-os_unknown-discovered-tap': 0
# }


summary = {
            'timestamp': 0
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
    logging.debug('key: {} - value: {}'.format(key, var[key]))



def get_os(var=None):
    if 'windows' in var.lower():
        return 'os_windows'
    elif re.match(linux_regex, var):
        return 'os_linux'
    else:
        logging.debug('unknown os: {}'.format(var.lower()))
        return 'os_unknown'


def get_status(var=None, name=None):
    if name is None:
        raise NameError('name variable is Null')
    else:
        if 'on,' in var.lower() or var.lower() == 'on':
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


def paged_search_computers(api=api, configuration=configuration, api_version=api_version, api_exception=None):
    # https://github.com/deep-security/automation-center-sdk-samples/blob/master/python/src/search_examples.py
    """ Uses a search filter to create a paged list of computers
    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :return: A list of computer objects
    """

    # Set search criteria
    search_criteria = api.SearchCriteria()
    search_criteria.id_value = 0
    search_criteria.id_test = "greater-than"

    # Create a search filter with maximum returned items
 
    search_filter = api.SearchFilter()
    search_filter.max_items = page_size
    search_filter.search_criteria = [search_criteria]

    # Include the minimum information in the returned Computer objects
    expand = api.Expand(api.Expand.all)

    # Perform the search and do work on the results
    computers_api = api.ComputersApi(api.ApiClient(configuration))
    paged_computers = []

    while True:
        computers = computers_api.search_computers(
            api_version, search_filter=search_filter, expand=expand.list(), overrides=False)
        num_found = len(computers.computers)
        current_paged_computers = []
        logging.info('paged_search_computers - listing with page size {}'.format(page_size))

        if num_found == 0:
            logging.info('paged_search_computers - No computers found.')
            break

        for computer in computers.computers:
            logging.debug(computer)
            current_paged_computers.append(computer)
            paged_computers.append(computer)

        # paged_computers.append(current_paged_computers)

        # Get the ID of the last computer in the page and return it with the number of computers on the page
        last_id = computers.computers[-1].id
        search_criteria.id_value = last_id
        logging.info("paged_search_computers - Last ID: {} Computers found: {}".format(str(last_id),
                                                                                       str(num_found)))

    return paged_computers


def ds_summary():
    active = {}
    warning = {}
    inactive = {}
    offline = {}
    error = {}
    unknown = {}
    total = 0
    active_total = 0
    ips_rules_total = 0 
    ips_rules_active_total = 0
    ips_rules_inactive_total = 0
    ips_rules_warning_total = 0
    ips_rules_error_total = 0
    ips_rules_unknown_total = 0


    # api_instance = api.ComputersApi(api.ApiClient(configuration))
    # overrides = False
    # logging.info('ds_summary: calling ds api')
    # api_response = api_instance.list_computers(
    #     api_version, overrides=overrides)


    logging.info('ds_summary: calling ds api')
    computers = paged_search_computers()


    logging.info('ds_summary: metric calc')
    for computer in computers:
        try:
            platform = computer.platform.lower()
            agent_status = computer.computer_status.agent_status.lower()
            agent_message = str(computer.computer_status.agent_status_messages).lower()
            agent_version_major = int(computer.agent_version.split('.')[0])
            agent_version = computer.agent_version
            os_type = get_os(platform)

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
            ips_status = None
            ips_mode = None
            ips_rules = 0

            
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
                else:
                    # not activated, 'off, installed, 2 rules' and 'off, not installed, no rules' will match this case
                    ips_status = 'discovered'
                    logging.debug('ips_status - not prevent|detect: {}'.format(
                        computer.intrusion_prevention.module_status.agent_status_message.lower()))


                if 'inline' in agent_mode and not 'inactive' in module_agent_status:
                    ips_mode = 'inline'
                elif 'tap' in agent_mode and not 'inactive' in module_agent_status:
                    ips_mode = 'tap'

            ips_rules_total += ips_rules
            if agent_status == 'active':
                active_total += 1
                ips_rules_active_total += ips_rules

                add_key(key='computer-platform-all-{}'.format(platform), var=active)
                add_key(key='computer-platform-{}-{}'.format(os_type, platform), var=active)

                add_key(key='computer-os_type-all-all', var=active)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=active)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=active)
   
                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=active)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=active)
                add_key(
                    key='computer-agent_version_major-all-{}'.format(agent_version_major), var=active)
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
                ips_rules_warning_total += ips_rules

                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=warning)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=warning)

                add_key(key='computer-os_type-all-all', var=warning)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=warning)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=warning)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=warning)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=warning)
                add_key(
                    key='computer-agent_version_major-all-{}'.format(agent_version_major), var=warning)
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
                ips_rules_inactive_total += ips_rules

                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=inactive)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=inactive)

                add_key(key='computer-os_type-all-all', var=inactive)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=inactive)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=inactive)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=inactive)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=inactive)
                add_key(
                    key='computer-agent_version_major-all-{}'.format(agent_version_major), var=inactive)
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
                ips_rules_error_total += ips_rules

                add_key(key=get_status(agent_version, 'computer-platform-all-{}'.format(platform)), var=error)
                add_key(key=get_status(agent_version, 'computer-platform-{}-{}'.format(os_type, platform)), var=error)

                add_key(key='computer-os_type-all-all', var=error)
                add_key(key='computer-os_type-{}-all'.format(os_type), var=error)
                add_key(key='computer-os_type-{}-{}'.format(os_type, platform), var=error)

                add_key(key='computer-agent_version-all-{}'.format(agent_version), var=error)
                add_key(key='computer-agent_version-{}-{}'.format(os_type, agent_version), var=error)
                add_key(
                    key='computer-agent_version_major-all-{}'.format(agent_version_major), var=error)
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
                add_key(key='vulnerabilities-ips_rules-{}-all-all'.format(
                    os_type), var=error, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-{}-all'.format(
                    ips_status), var=error, value=ips_rules)
                add_key(key='vulnerabilities-ips_rules-all-all-{}'.format(
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
                logging.debug('unknown computer: {}'.format(computer.host_name))
                ips_rules_unknown_total += ips_rules

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
                add_key(
                    key='computer-agent_version_major-all-{}'.format(agent_version_major), var=unknown)
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

    # print_dict(active, 'active')
    # print('active hosts: {}'.format(active_total))
    # print_dict(inactive, 'inactive')
    # print_dict(warning, 'warning')
    # print_dict(error, 'error')
    # print_dict(unknown, 'unknown')
    # print_dict(offline, 'offline')

    # print('total: {}'.format(total))
    logging.info('total ips rules found - active agents: {}'.format(ips_rules_active_total))
    logging.info(
        'total ips rules found - inactive agents: {}'.format(ips_rules_inactive_total))
    logging.info(
        'total ips rules found - warning agents: {}'.format(ips_rules_warning_total))
    logging.info(
        'total ips rules found - error agents: {}'.format(ips_rules_error_total))
    logging.info(
        'total ips rules found - unknown agents: {}'.format(ips_rules_unknown_total))
    logging.info('total ips rules found: {}'.format(ips_rules_total))

    summary = { 
                'timestamp': datetime.now(), 
                'managed': active,
                'warning': warning, 
                'unmanaged': inactive, 
                'critical': error, 
                'offline': offline, 
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
