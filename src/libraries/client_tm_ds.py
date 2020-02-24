import deepsecurity as api
import datetime
from deepsecurity.rest import ApiException as api_exception
from pprint import pprint
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

# Add the DSM information to the API client configuration
configuration = api.Configuration() # Create a Configuration object
configuration.host = environ.get("DS_HOST", default=config.DS_HOST)  # Set the URL of the DSM
configuration.api_key['api-secret-key'] = environ.get("DS_API_KEY", default=config.DS_API_KEY)  # Set the secret key for the DSM
configuration.verify_ssl = environ.get("DS_VERIFY_SSL", default=config.DS_VERIFY_SSL)

# Add the API version to a global variable
api_version = environ.get("DS_API_VERSION", default=config.DS_API_VERSION)

# Add any additional global variables that will be shared across your functions
# Variables for Settings examples
settings_policy_id = 9

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
        delta = divmod(difference.days * seconds_in_day + difference.seconds, 60)
        # (0, 8)      # 0 minutes, 8 seconds
        # print('min: {}'.format(delta[0]))
        # print('sec: {}'.formart(delta[1]))
        return delta[0]
    except Exception as e:
        print('delta_date_error: {}'.format(e))


def get_summary(max_time=60):
    global summary
    try:
        delta_time =  delta_date(summary['timestamp'])
        if delta_time >= max_time:
            print('not_valid_delta_date_seconds: {}'.format(delta_time))
            return ds_summary()
        else:
            print('valid_delta_date_seconds: {}'.format(delta_time))
            return summary
    except Exception as e:
        print('check_timestamp_error: {}'.format(e))


def ds_summary():
    total = 0
    am_count = 0
    wr_count = 0
    fw_count = 0
    ip_count = 0
    im_count = 0
    li_count = 0
    managed_count = 0
    managed_online = 0
    managed_offline = 0
    os_linux = 0
    os_windows = 0
    os_linux_managed = 0
    os_linux_unmanaged = 0
    os_windows_managed = 0
    os_windows_unmanaged = 0
    os_windows_server = 0 
    os_windows_desktop = 0
    os_unknown = 0
    computer_status_set = set()
    computer_status_list = []
    agent_version_set = set()
    agent_version_list = []
    agent_firewall_setting_network_engine_mode_set = set()
    agent_firewall_setting_network_engine_mode_list = []
    platform_set = set()
    platform_list = []
    vulnerabilities_detected = 0
    vulnerabilities_protected = 0
    vulnerabilities_protected_inline = 0
    vulnerabilities_protected_tap = 0

    vulnerabilities_detected_windows = 0
    vulnerabilities_detected_windows_online = 0
    vulnerabilities_detected_windows_offline = 0
    vulnerabilities_protected_windows = 0
    vulnerabilities_protected_windows_online = 0
    vulnerabilities_protected_windows_offline = 0
    vulnerabilities_protected_inline_windows = 0
    vulnerabilities_protected_tap_windows = 0

    vulnerabilities_detected_linux = 0
    vulnerabilities_detected_linux_online = 0
    vulnerabilities_detected_linux_offline = 0
    vulnerabilities_protected_linux = 0
    vulnerabilities_protected_linux_online = 0
    vulnerabilities_protected_linux_offline = 0
    vulnerabilities_protected_inline_linux = 0
    vulnerabilities_protected_tap_linux = 0

    vulnerabilities_detected_unknown = 0
    vulnerabilities_detected_unknown_online = 0
    vulnerabilities_detected_unknown_offline = 0
    vulnerabilities_protected_unknown = 0
    vulnerabilities_protected_unknown_online = 0
    vulnerabilities_protected_unknown_offline = 0
    vulnerabilities_protected_inline_unknown = 0
    vulnerabilities_protected_tap_unknown = 0

    api_instance = api.ComputersApi(api.ApiClient(configuration))
    overrides = False
    api_response = api_instance.list_computers(api_version, overrides=overrides)

    for computer in api_response.computers:
        try:
            total += 1
            if "managed" in str(computer.computer_status.agent_status_messages).lower():
                managed_count += 1
            if "managed" in str(computer.computer_status.agent_status_messages).lower() and "online" in str(computer.computer_status.agent_status_messages).lower():
                managed_online += 1
            if "managed" in str(computer.computer_status.agent_status_messages).lower() and not "online" in str(computer.computer_status.agent_status_messages).lower():
                managed_offline += 1
            if "on" in str(computer.anti_malware.module_status.agent_status_message).lower():
                am_count += 1
            if "on" in str(computer.web_reputation.module_status.agent_status_message).lower():
                wr_count += 1
            if "on" in str(computer.firewall.module_status.agent_status_message).lower():
                fw_count += 1
            if "on" in str(computer.intrusion_prevention.module_status.agent_status_message).lower():
                ip_count += 1
            if "on" in str(computer.integrity_monitoring.module_status.agent_status_message).lower():
                im_count += 1
            if "on" in str(computer.log_inspection.module_status.agent_status_message).lower():
                li_count += 1

            platform = computer.platform.lower()

            if computer.intrusion_prevention.rule_ids is not None:
                vulnerabilities_detected = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected
                if "windows" in platform:
                    vulnerabilities_detected_windows = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_windows
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_detected_windows_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_windows_online
                    else:
                        vulnerabilities_detected_windows_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_windows_offline
                elif re.match('linux|debian|ubuntu|oracle|centos|red\shat', platform):
                    vulnerabilities_detected_linux = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_linux
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_detected_linux_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_linux_online
                    else:
                        vulnerabilities_detected_linux_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_linux_offline
                elif "unknown" in platform:
                    vulnerabilities_detected_unknown = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_unknown
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_detected_unknown_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_unknown_online
                    else:
                        vulnerabilities_detected_unknown_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_detected_unknown_offline
            # if ("prevent" in str(computer.intrusion_prevention.module_status.agent_status_message).lower()) \
            #         and ("active" in str(computer.computer_status.agent_status)):
            if "prevent" in computer.intrusion_prevention.module_status.agent_status_message.lower():
                vulnerabilities_protected = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected
                if "windows" in platform:
                    vulnerabilities_protected_windows = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_windows
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_protected_windows_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_windows_online
                    else:
                        vulnerabilities_protected_windows_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_windows_offline
                elif re.match('linux|debian|ubuntu|oracle|centos|red\shat', platform):
                    vulnerabilities_protected_linux = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_linux
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_protected_linux_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_linux_online
                    else:
                        vulnerabilities_protected_linux_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_linux_offline
                elif "unknown" in platform:
                    vulnerabilities_protected_unknown = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_unknown
                    if "online" in str(computer.computer_status.agent_status_messages).lower():
                        vulnerabilities_protected_unknown_online = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_unknown_online
                    else:
                        vulnerabilities_protected_unknown_offline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_unknown_offline
                
                if "prevent" in computer.intrusion_prevention.module_status.agent_status_message.lower() and "inline" in computer.computer_settings.firewall_setting_network_engine_mode.value.lower():
                    vulnerabilities_protected_inline = len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_inline
                elif  "prevent" in computer.intrusion_prevention.module_status.agent_status_message.lower() and "tap" in computer.computer_settings.firewall_setting_network_engine_mode.value.lower():
                    vulnerabilities_protected_tap += len(computer.intrusion_prevention.rule_ids) + vulnerabilities_protected_tap

            agent_version_list.append(str(computer.agent_version))
            agent_version_set.add(str(computer.agent_version))

            agent_firewall_setting_network_engine_mode_list.append(computer.computer_settings.firewall_setting_network_engine_mode.value)
            agent_firewall_setting_network_engine_mode_set.add(computer.computer_settings.firewall_setting_network_engine_mode.value)

            computer_status_list.append(computer.computer_status.agent_status)
            computer_status_set.add(computer.computer_status.agent_status)

            platform_list.append(computer.platform)
            platform_set.add(computer.platform)

            if "windows" in platform:
                os_windows += 1
                if "managed" in str(computer.computer_status.agent_status_messages).lower():
                    os_windows_managed += 1
                else:
                    os_windows_unmanaged += 1
                if "server" in platform:
                    os_windows_server += 1
                else:
                    os_windows_desktop += 1
            elif re.match('linux|debian|ubuntu|oracle|centos|red\shat', platform):
                os_linux += 1
                if "managed" in str(computer.computer_status.agent_status_messages).lower():
                    os_linux_managed += 1
                else:
                    os_linux_unmanaged += 1
            elif "unknown" in platform:
                os_unknown += 1

        except Exception as e:
            print(e)

        print("-------------------------------------------------------")

    message = "I am giving you a summary of your environment protected by Trend Micro Security Platform:\n" \
                "total computers: {}\n" \
                "managed_agents: {}\n" \
                "managed_online_agents: {}\n" \
                "managed_offline_agents: {}\n" \
                "os_windows: {}\n" \
                "os_linux: {}\n" \
                "os_unknown: {}\n" \
                "antimalware agents: {}\n" \
                "web_reputation agents: {}\n" \
                "firewall agents: {}\n" \
                "intrusion_prevention agents: {}\n" \
                "vulnerabilities detected: {}\n" \
                "vulnerabilities detected_windows: {}\n" \
                "vulnerabilities detected_windows_online: {}\n" \
                "vulnerabilities detected_windows_offline: {}\n" \
                "vulnerabilities detected_linux: {}\n" \
                "vulnerabilities detected_linux_online: {}\n" \
                "vulnerabilities detected_linux_offline: {}\n" \
                "vulnerabilities detected_unknown: {}\n" \
                "vulnerabilities detected_unknown_online: {}\n" \
                "vulnerabilities detected_unknown_offiline: {}\n" \
                "vulnerabilities protected: {}\n" \
                "vulnerabilities protected_windows: {}\n" \
                "vulnerabilities protected_windows_online: {}\n" \
                "vulnerabilities protected_windows_offline: {}\n" \
                "vulnerabilities protected_linux: {}\n" \
                "vulnerabilities protected_linux_online: {}\n" \
                "vulnerabilities protected_linux_offline: {}\n" \
                "vulnerabilities protected_unknown: {}\n" \
                "vulnerabilities protected_unknown_online: {}\n" \
                "vulnerabilities protected_unknown_offiline: {}\n" \
                "vulnerabilities protected_inline: {}\n" \
                "vulnerabilities protected_tap: {}\n" \
                "integrity_monitoring agents: {}\n" \
                "log_inspection agents: {}\n".format(total, managed_count, managed_online, managed_offline, 
                                                     os_windows, os_linux, os_unknown,
                                                     am_count, wr_count, fw_count, ip_count,
                                                     vulnerabilities_detected, vulnerabilities_detected_windows,
                                                     vulnerabilities_detected_windows_online, vulnerabilities_detected_windows_offline,
                                                     vulnerabilities_detected_linux,
                                                     vulnerabilities_detected_linux_online, vulnerabilities_detected_linux_offline,
                                                     vulnerabilities_detected_unknown,
                                                     vulnerabilities_detected_unknown_online, vulnerabilities_detected_unknown_offline,
                                                     vulnerabilities_protected, vulnerabilities_protected_windows,
                                                     vulnerabilities_protected_windows_online, vulnerabilities_protected_windows_offline,
                                                     vulnerabilities_protected_linux,
                                                     vulnerabilities_protected_linux_online, vulnerabilities_protected_linux_offline,
                                                     vulnerabilities_protected_unknown,
                                                     vulnerabilities_protected_unknown_online, vulnerabilities_protected_unknown_offline,
                                                     vulnerabilities_protected_inline, vulnerabilities_protected_tap,
                                                     im_count, li_count)

    for i in agent_version_set:
        agent_message = "{}: {}\n".format(i, agent_version_list.count(i))
        message = message + agent_message

    for i in agent_firewall_setting_network_engine_mode_set:
        agent_firewall_setting_network_engine_mode = "network engine - {}: {}\n".format(i, agent_firewall_setting_network_engine_mode_list.count(i))
        message = message + agent_firewall_setting_network_engine_mode

    for i in computer_status_set:
        computer_status_message = "agent_status - {}: {}\n".format(i, computer_status_list.count(i))
        message = message + computer_status_message

    for i in platform_set:
        platform_message = "platform - {}: {}\n".format(i, platform_list.count(i))
        message = message + platform_message

    print(message)

    summary = {
                'timestamp': datetime.now(),
                'total': total, 
                'managed_count': managed_count, 
                'managed_online': managed_online, 
                'managed_offline': managed_offline, 
                'os_windows': os_windows, 
                'os_linux': os_linux, 
                'os_windows_managed': os_windows_managed, 
                'os_linux_managed': os_linux_managed, 
                'os_windows_unmanaged': os_windows_unmanaged, 
                'os_linux_unmanaged': os_linux_unmanaged, 
                'os_unknown': os_unknown,
                'am_count': am_count, 
                'wr_count': wr_count, 
                'fw_count': fw_count, 
                'ip_count': ip_count,
                'im_count': im_count, 
                'li_count': li_count,
                'vulnerabilities_detected': vulnerabilities_detected, 
                'vulnerabilities_detected_windows': vulnerabilities_detected_windows, 
                'vulnerabilities_detected_linux': vulnerabilities_detected_linux,
                'vulnerabilities_detected_unknown': vulnerabilities_detected_unknown,
                'vulnerabilities_detected_windows_online': vulnerabilities_detected_windows_online, 
                'vulnerabilities_detected_linux_online': vulnerabilities_detected_linux_online,
                'vulnerabilities_detected_unknown_online': vulnerabilities_detected_unknown_online,
                'vulnerabilities_detected_windows_offline': vulnerabilities_detected_windows_offline, 
                'vulnerabilities_detected_linux_offline': vulnerabilities_detected_linux_offline,
                'vulnerabilities_detected_unknown_offline': vulnerabilities_detected_unknown_offline,
                'vulnerabilities_protected': vulnerabilities_protected,
                'vulnerabilities_protected_windows': vulnerabilities_protected_windows, 
                'vulnerabilities_protected_linux': vulnerabilities_protected_linux,
                'vulnerabilities_protected_unknown': vulnerabilities_protected_unknown,
                'vulnerabilities_protected_windows_online': vulnerabilities_protected_windows_online, 
                'vulnerabilities_protected_linux_online': vulnerabilities_protected_linux_online,
                'vulnerabilities_protected_unknown_online': vulnerabilities_protected_unknown_online,
                'vulnerabilities_protected_windows_offline': vulnerabilities_protected_windows_offline, 
                'vulnerabilities_protected_linux_offline': vulnerabilities_protected_linux_offline,
                'vulnerabilities_protected_unknown_offline': vulnerabilities_protected_unknown_offline,
                'vulnerabilities_protected_inline': vulnerabilities_protected_inline,
                'vulnerabilities_protected_tap': vulnerabilities_protected_tap
    }

    return summary

summary = ds_summary()

def main():
    ''' Run the examples from the Create and Configure Policies guide

    Each function call passes the api client configuration information
    and any required variables and prints their output.
    '''
    # ds_summary()



if __name__ == '__main__':
    main()
