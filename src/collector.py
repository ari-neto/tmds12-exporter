import time
from prometheus_client.core import GaugeMetricFamily, REGISTRY, CounterMetricFamily, Counter
from prometheus_client import start_http_server
from os import environ
import logging
import signal
import sys
import config
import libraries.client_tm_ds as ds
from datetime import datetime

# Logging configuration
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=config.LOG_LEVEL)

server_port = environ.get('SERVER_PORT', default=config.SERVER_PORT)
# max valid period of api retrieved data - in seconds
ds_api_check = environ.get('DS_API_INTERVAL', default=config.DS_API_CHECK)
sleep = 15

# https://github.com/jakirpatel/prometheus-custom-collector/blob/master/code/collector.py
class CustomCollector(object):
    def __init__(self):
        pass

    def collect(self):
        ds_metrics = ds.get_summary(ds_api_check)

        vulnerabilities_exposed = int(ds_metrics['vulnerabilities_detected']) - int(ds_metrics['vulnerabilities_protected'])
        vulnerabilities_exposed_windows = int(ds_metrics['vulnerabilities_detected_windows']) - int(ds_metrics['vulnerabilities_protected_windows'])
        vulnerabilities_exposed_linux = int(ds_metrics['vulnerabilities_detected_linux']) - int(ds_metrics['vulnerabilities_protected_linux'])
        vulnerabilities_exposed_unknown = int(ds_metrics['vulnerabilities_detected_unknown']) - int(ds_metrics['vulnerabilities_protected_unknown'])

        vulnerabilities_exposed_windows_online = int(ds_metrics['vulnerabilities_detected_windows_online']) - int(ds_metrics['vulnerabilities_protected_windows_online'])
        vulnerabilities_exposed_linux_online = int(ds_metrics['vulnerabilities_detected_linux_online']) - int(ds_metrics['vulnerabilities_protected_linux_online'])
        vulnerabilities_exposed_unknown_online = int(ds_metrics['vulnerabilities_detected_unknown_online']) - int(ds_metrics['vulnerabilities_protected_unknown_online'])

        vulnerabilities_exposed_windows_offline = int(ds_metrics['vulnerabilities_detected_windows_offline']) - int(ds_metrics['vulnerabilities_protected_windows_offline'])
        vulnerabilities_exposed_linux_offline = int(ds_metrics['vulnerabilities_detected_linux_offline']) - int(ds_metrics['vulnerabilities_protected_linux_offline'])
        vulnerabilities_exposed_unknown_offline = int(ds_metrics['vulnerabilities_detected_unknown_offline']) - int(ds_metrics['vulnerabilities_protected_unknown_offline'])

        vulnerabilities_exposed_online = vulnerabilities_exposed_windows_online + vulnerabilities_exposed_linux_online + vulnerabilities_exposed_unknown_online 
        vulnerabilities_exposed_offline = vulnerabilities_exposed_windows_offline + vulnerabilities_exposed_linux_offline + vulnerabilities_exposed_unknown_offline 

        tm_ds = CounterMetricFamily('deep_security', 'Deep Security Computer Metrics', labels=['metric','type','status','platform','mode'])
        tm_ds.add_metric(['computers','all','all','all','all'], int(ds_metrics['total']))
        tm_ds.add_metric(['computers','managed','all','all','all'], int(ds_metrics['managed_count']))
        tm_ds.add_metric(['computers','unmanaged','all','all','all'], int(ds_metrics['total']) - int(ds_metrics['managed_count']))
        tm_ds.add_metric(['computers','managed','online','all','all'], int(ds_metrics['managed_online']))
        tm_ds.add_metric(['computers','managed','offline','all','all'], int(ds_metrics['managed_offline']))

        tm_ds.add_metric(['computers','managed','online','windows','all'], int(ds_metrics['managed_windows_online']))
        tm_ds.add_metric(['computers','managed','offline','windows','all'], int(ds_metrics['managed_windows_offline']))

        tm_ds.add_metric(['computers','managed','online','linux','all'], int(ds_metrics['managed_linux_online']))
        tm_ds.add_metric(['computers','managed','offline','linux','all'], int(ds_metrics['managed_linux_offline']))

        tm_ds.add_metric(['computers','managed','online','unknown','all'], int(ds_metrics['managed_unknown_online']))
        tm_ds.add_metric(['computers','managed','offline','unknown','all'], int(ds_metrics['managed_unknown_offline']))

        tm_ds.add_metric(['computers','managed','all','linux','all'], int(ds_metrics['os_linux_managed']))
        tm_ds.add_metric(['computers','managed','all','windows','all'], int(ds_metrics['os_windows_managed']))
        tm_ds.add_metric(['computers','unmanaged','all','linux','all'], int(ds_metrics['os_linux_unmanaged']))
        tm_ds.add_metric(['computers','unmanaged','all','windows','all'], int(ds_metrics['os_windows_unmanaged']))  
        tm_ds.add_metric(['computers','all','all','windows','all'], int(ds_metrics['os_windows']))
        tm_ds.add_metric(['computers','all','all','linux','all'], int(ds_metrics['os_linux']))
        tm_ds.add_metric(['computers','all','all','unknown','all'], int(ds_metrics['os_unknown']))

        tm_ds.add_metric(['antimalware_clients','all','all','all','all'], int(ds_metrics['am_count']))
        tm_ds.add_metric(['web_reputation_clients','all','all','all','all'], int(ds_metrics['wr_count']))
        tm_ds.add_metric(['firewall_clients','all','all','all','all'], int(ds_metrics['fw_count']))
        tm_ds.add_metric(['ips_clients','all','all','all','all'], int(ds_metrics['ip_count']))
        tm_ds.add_metric(['integrity_monitoring_clients','all','all','all','all'], int(ds_metrics['im_count']))
        tm_ds.add_metric(['log_inspection_clients','all','all','all','all'], int(ds_metrics['li_count']))
        
        tm_ds.add_metric(['antimalware_clients','managed','all','all','all'], int(ds_metrics['am_count_managed']))
        tm_ds.add_metric(['antimalware_clients','managed','online','all','all'], int(ds_metrics['am_count_managed_online']))
        tm_ds.add_metric(['antimalware_clients','managed','offline','all','all'], int(ds_metrics['am_count_managed_offline']))

        tm_ds.add_metric(['web_reputation_clients','managed','all','all','all'], int(ds_metrics['wr_count_managed']))
        tm_ds.add_metric(['web_reputation_clients','managed','online','all','all'], int(ds_metrics['wr_count_managed_online']))
        tm_ds.add_metric(['web_reputation_clients','managed','offline','all','all'], int(ds_metrics['wr_count_managed_offline']))

        tm_ds.add_metric(['firewall_clients','managed','all','all','all'], int(ds_metrics['fw_count_managed']))
        tm_ds.add_metric(['firewall_clients','managed','online','all','all'], int(ds_metrics['fw_count_managed_online']))
        tm_ds.add_metric(['firewall_clients','managed','offline','all','all'], int(ds_metrics['fw_count_managed_offline']))

        tm_ds.add_metric(['ips_clients','managed','all','all','all'], int(ds_metrics['ip_count_managed']))
        tm_ds.add_metric(['ips_clients','managed','online','all','all'], int(ds_metrics['ip_count_managed_online']))
        tm_ds.add_metric(['ips_clients','managed','offline','all','all'], int(ds_metrics['ip_count_managed_offline']))

        tm_ds.add_metric(['integrity_monitoring_clients','managed','all','all','all'], int(ds_metrics['im_count_managed']))
        tm_ds.add_metric(['integrity_monitoring_clients','online','all','all','all'], int(ds_metrics['im_count_managed_online']))
        tm_ds.add_metric(['integrity_monitoring_clients','offline','all','all','all'], int(ds_metrics['im_count_managed_offline']))

        tm_ds.add_metric(['log_inspection_clients','managed','all','all','all'], int(ds_metrics['li_count_managed']))
        tm_ds.add_metric(['log_inspection_clients','online','all','all','all'], int(ds_metrics['li_count_managed_online']))
        tm_ds.add_metric(['log_inspection_clients','offline','all','all','all'], int(ds_metrics['li_count_managed_offline']))

        tm_ds.add_metric(['vulnerabilities','detected','all','all','all'], int(ds_metrics['vulnerabilities_detected']))
        tm_ds.add_metric(['vulnerabilities','detected','online','all','all'], int(ds_metrics['vulnerabilities_detected_windows_online'])+ int(ds_metrics['vulnerabilities_detected_linux_online'])+ int(ds_metrics['vulnerabilities_detected_unknown_online']))
        tm_ds.add_metric(['vulnerabilities','detected','offline','all','all'], int(ds_metrics['vulnerabilities_detected_windows_offline'])+ int(ds_metrics['vulnerabilities_detected_linux_offline'])+ int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        tm_ds.add_metric(['vulnerabilities','protected','all','all','all'], int(ds_metrics['vulnerabilities_protected']))
        tm_ds.add_metric(['vulnerabilities','protected','online','all','all'], int(ds_metrics['vulnerabilities_protected_windows_online'])+ int(ds_metrics['vulnerabilities_protected_linux_online'])+ int(ds_metrics['vulnerabilities_detected_unknown_online']))
        tm_ds.add_metric(['vulnerabilities','protected','offline','all','all'], int(ds_metrics['vulnerabilities_protected_windows_offline'])+ int(ds_metrics['vulnerabilities_protected_linux_offline'])+ int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        tm_ds.add_metric(['vulnerabilities','exposed','all','all','all'], vulnerabilities_exposed)
        tm_ds.add_metric(['vulnerabilities','protected','all','all','inline'], int(ds_metrics['vulnerabilities_protected_inline']))
        tm_ds.add_metric(['vulnerabilities','protected','all','all','tap'], int(ds_metrics['vulnerabilities_protected_tap']))
        tm_ds.add_metric(['vulnerabilities','detected','all','windows','all'], int(ds_metrics['vulnerabilities_detected_windows']))
        tm_ds.add_metric(['vulnerabilities','protected','all','windows','all'], int(ds_metrics['vulnerabilities_protected_windows']))
        tm_ds.add_metric(['vulnerabilities','detected','online','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_online']))
        tm_ds.add_metric(['vulnerabilities','detected','offline','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_offline']))
        tm_ds.add_metric(['vulnerabilities','protected','online','windows','all'], int(ds_metrics['vulnerabilities_protected_windows_online']))
        tm_ds.add_metric(['vulnerabilities','protected','offline','windows','all'], int(ds_metrics['vulnerabilities_protected_windows_offline']))
        tm_ds.add_metric(['vulnerabilities','exposed','all','windows','all'], vulnerabilities_exposed_windows)
        tm_ds.add_metric(['vulnerabilities','exposed','online','windows','all'], vulnerabilities_exposed_windows_online)
        tm_ds.add_metric(['vulnerabilities','exposed','offline','windows','all'], vulnerabilities_exposed_windows_offline)
        tm_ds.add_metric(['vulnerabilities','detected','all','linux','all'], int(ds_metrics['vulnerabilities_detected_linux']))
        tm_ds.add_metric(['vulnerabilities','protected','all','linux','all'], int(ds_metrics['vulnerabilities_protected_linux']))
        tm_ds.add_metric(['vulnerabilities','detected','online','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_online']))
        tm_ds.add_metric(['vulnerabilities','detected','offline','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_offline']))
        tm_ds.add_metric(['vulnerabilities','protected','online','linux','all'], int(ds_metrics['vulnerabilities_protected_linux_online']))
        tm_ds.add_metric(['vulnerabilities','protected','offline','linux','all'], int(ds_metrics['vulnerabilities_protected_linux_offline']))
        tm_ds.add_metric(['vulnerabilities','exposed','all','linux','all'], vulnerabilities_exposed_linux)
        tm_ds.add_metric(['vulnerabilities','exposed','online','linux','all'], vulnerabilities_exposed_linux_online)
        tm_ds.add_metric(['vulnerabilities','exposed','offline','linux','all'], vulnerabilities_exposed_linux_offline)
        tm_ds.add_metric(['vulnerabilities','detected','all','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown']))
        tm_ds.add_metric(['vulnerabilities','protected','all','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown']))
        tm_ds.add_metric(['vulnerabilities','detected','online','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_online']))
        tm_ds.add_metric(['vulnerabilities','detected','offline','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        tm_ds.add_metric(['vulnerabilities','protected','online','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown_online']))
        tm_ds.add_metric(['vulnerabilities','protected','offline','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown_offline']))
        tm_ds.add_metric(['vulnerabilities','exposed','all','unknown','all'], vulnerabilities_exposed_unknown)
        tm_ds.add_metric(['vulnerabilities','exposed','online','unknown','all'], vulnerabilities_exposed_unknown_online)
        tm_ds.add_metric(['vulnerabilities','exposed','offline','unknown','all'], vulnerabilities_exposed_unknown_offline)

        tm_ds.add_metric(['vulnerabilities','exposed','online','all','all'], vulnerabilities_exposed_online)
        tm_ds.add_metric(['vulnerabilities','exposed','offline','all','all'], vulnerabilities_exposed_offline)
        yield tm_ds


        # tm_comp = CounterMetricFamily('deep_security_computer', 'Deep Security Computer Metrics', labels=['metric','type','status','platform'])
        # tm_comp.add_metric(['computers','all','all','all'], int(ds_metrics['total']))
        # tm_comp.add_metric(['computers','managed','all','all'], int(ds_metrics['managed_count']))
        # tm_comp.add_metric(['computers','unmanaged','all','all'], int(ds_metrics['total']) - int(ds_metrics['managed_count']))
        # tm_comp.add_metric(['computers','managed','online','all'], int(ds_metrics['managed_online']))
        # tm_comp.add_metric(['computers','managed','offline','all'], int(ds_metrics['managed_offline']))
        # tm_comp.add_metric(['computers','managed','all','linux'], int(ds_metrics['os_linux_managed']))
        # tm_comp.add_metric(['computers','managed','all','windows'], int(ds_metrics['os_windows_managed']))
        # tm_comp.add_metric(['computers','unmanaged','all','linux'], int(ds_metrics['os_linux_unmanaged']))
        # tm_comp.add_metric(['computers','unmanaged','all','windows'], int(ds_metrics['os_windows_unmanaged']))  
        # tm_comp.add_metric(['computers','all','all','windows'], int(ds_metrics['os_windows']))
        # tm_comp.add_metric(['computers','all','all','linux'], int(ds_metrics['os_linux']))
        # tm_comp.add_metric(['computers','all','all','unknown'], int(ds_metrics['os_unknown']))
        # yield tm_comp

        # tm_mod = CounterMetricFamily('deep_security_modules', 'Deep Security Module Metrics', labels=['metric','type','status','platform'])
        # tm_mod.add_metric(['antimalware_clients','all','all','all'], int(ds_metrics['am_count']))
        # tm_mod.add_metric(['web_reputation_clients','all','all','all'], int(ds_metrics['wr_count']))
        # tm_mod.add_metric(['firewall_clients','all','all','all'], int(ds_metrics['fw_count']))
        # tm_mod.add_metric(['ips_clients','all','all','all'], int(ds_metrics['ip_count']))
        # tm_mod.add_metric(['integrity_monitoring_clients','all','all','all'], int(ds_metrics['im_count']))
        # tm_mod.add_metric(['log_inspection_clients','all','all','all'], int(ds_metrics['li_count']))
        # yield tm_mod

        # tm_vul = CounterMetricFamily('deep_security_protection', 'Deep Security Protection Metrics', labels=['metric','type','status','platform','mode'])
        # tm_vul.add_metric(['vulnerabilities','detected','all','all','all'], int(ds_metrics['vulnerabilities_detected']))
        # tm_vul.add_metric(['vulnerabilities','protected','all','all','all'], int(ds_metrics['vulnerabilities_protected']))
        # tm_vul.add_metric(['vulnerabilities','exposed','all','all','all'], int(ds_metrics['vulnerabilities_detected'] - int(ds_metrics['vulnerabilities_protected'])))
        # tm_vul.add_metric(['vulnerabilities','protected','all','all','inline'], int(ds_metrics['vulnerabilities_protected_inline']))
        # tm_vul.add_metric(['vulnerabilities','protected','all','all','tap'], int(ds_metrics['vulnerabilities_protected_tap']))
        # tm_vul.add_metric(['vulnerabilities','detected','all','windows','all'], int(ds_metrics['vulnerabilities_detected_windows']))
        # tm_vul.add_metric(['vulnerabilities','protected','all','windows','all'], int(ds_metrics['vulnerabilities_protected_windows']))
        # tm_vul.add_metric(['vulnerabilities','detected','online','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_online']))
        # tm_vul.add_metric(['vulnerabilities','detected','offline','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_offline']))
        # tm_vul.add_metric(['vulnerabilities','protected','online','windows','all'], int(ds_metrics['vulnerabilities_protected_windows_online']))
        # tm_vul.add_metric(['vulnerabilities','protected','offline','windows','all'], int(ds_metrics['vulnerabilities_protected_windows_offline']))
        # tm_vul.add_metric(['vulnerabilities','exposed','all','windows','all'], int(ds_metrics['vulnerabilities_detected_windows'] - int(ds_metrics['vulnerabilities_protected_windows'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','online','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_online'] - int(ds_metrics['vulnerabilities_protected_windows_online'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','offline','windows','all'], int(ds_metrics['vulnerabilities_detected_windows_offline'] - int(ds_metrics['vulnerabilities_protected_windows_offline'])))
        # tm_vul.add_metric(['vulnerabilities','detected','all','linux','all'], int(ds_metrics['vulnerabilities_detected_linux']))
        # tm_vul.add_metric(['vulnerabilities','protected','all','linux','all'], int(ds_metrics['vulnerabilities_protected_linux']))
        # tm_vul.add_metric(['vulnerabilities','detected','online','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_online']))
        # tm_vul.add_metric(['vulnerabilities','detected','offline','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_offline']))
        # tm_vul.add_metric(['vulnerabilities','protected','online','linux','all'], int(ds_metrics['vulnerabilities_protected_linux_online']))
        # tm_vul.add_metric(['vulnerabilities','protected','offline','linux','all'], int(ds_metrics['vulnerabilities_protected_linux_offline']))
        # tm_vul.add_metric(['vulnerabilities','exposed','all','linux','all'], int(ds_metrics['vulnerabilities_detected_linux'] - int(ds_metrics['vulnerabilities_protected_linux'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','online','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_online'] - int(ds_metrics['vulnerabilities_protected_linux_online'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','offline','linux','all'], int(ds_metrics['vulnerabilities_detected_linux_offline'] - int(ds_metrics['vulnerabilities_protected_linux_offline'])))
        # tm_vul.add_metric(['vulnerabilities','detected','all','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown']))
        # tm_vul.add_metric(['vulnerabilities','protected','all','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown']))
        # tm_vul.add_metric(['vulnerabilities','detected','online','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_online']))
        # tm_vul.add_metric(['vulnerabilities','detected','offline','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        # tm_vul.add_metric(['vulnerabilities','protected','online','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown_online']))
        # tm_vul.add_metric(['vulnerabilities','protected','offline','unknown','all'], int(ds_metrics['vulnerabilities_protected_unknown_offline']))
        # tm_vul.add_metric(['vulnerabilities','exposed','all','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown'] - int(ds_metrics['vulnerabilities_protected_unknown'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','online','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_online'] - int(ds_metrics['vulnerabilities_protected_unknown_online'])))
        # tm_vul.add_metric(['vulnerabilities','exposed','offline','unknown','all'], int(ds_metrics['vulnerabilities_detected_unknown_offline'] - int(ds_metrics['vulnerabilities_protected_unknown_offline'])))
        # yield tm_vul

        tm = CounterMetricFamily('deep_security', 'Deep Security Metrics', labels=['metric'])
        tm.add_metric(['total_hosts'], int(ds_metrics['total']))
        tm.add_metric(['managed_hosts'], int(ds_metrics['managed_count']))
        tm.add_metric(['unmanaged_hosts'], int(ds_metrics['total']) - int(ds_metrics['managed_count']))
        tm.add_metric(['managed_online'], int(ds_metrics['managed_online']))
        tm.add_metric(['managed_offline'], int(ds_metrics['managed_offline']))
        tm.add_metric(['managed_linux'], int(ds_metrics['os_linux_managed']))
        tm.add_metric(['managed_windows'], int(ds_metrics['os_windows_managed']))
        tm.add_metric(['unmanaged_linux'], int(ds_metrics['os_linux_unmanaged']))
        tm.add_metric(['unmanaged_windows'], int(ds_metrics['os_windows_unmanaged']))    
        tm.add_metric(['total_windows'], int(ds_metrics['os_windows']))
        tm.add_metric(['total_linux'], int(ds_metrics['os_linux']))
        tm.add_metric(['total_unknown'], int(ds_metrics['os_unknown']))

        tm.add_metric(['antimalware_clients'], int(ds_metrics['am_count']))
        tm.add_metric(['web_reputation_clients'], int(ds_metrics['wr_count']))
        tm.add_metric(['firewall_clients'], int(ds_metrics['fw_count']))
        tm.add_metric(['ips_clients'], int(ds_metrics['ip_count']))
        tm.add_metric(['integrity_monitoring_clients'], int(ds_metrics['im_count']))
        tm.add_metric(['log_inspection_clients'], int(ds_metrics['li_count']))

        tm.add_metric(['vulnerabilities_detected'], int(ds_metrics['vulnerabilities_detected']))
        tm.add_metric(['vulnerabilities_protected'], int(ds_metrics['vulnerabilities_protected']))
        tm.add_metric(['vulnerabilities_exposed'], int(ds_metrics['vulnerabilities_detected'] - int(ds_metrics['vulnerabilities_protected'])))
        tm.add_metric(['vulnerabilities_protected_inline'], int(ds_metrics['vulnerabilities_protected_inline']))
        tm.add_metric(['vulnerabilities_protected_tap'], int(ds_metrics['vulnerabilities_protected_tap']))
        tm.add_metric(['vulnerabilities_detected_windows'], int(ds_metrics['vulnerabilities_detected_windows']))
        tm.add_metric(['vulnerabilities_protected_windows'], int(ds_metrics['vulnerabilities_protected_windows']))
        tm.add_metric(['vulnerabilities_detected_windows_online'], int(ds_metrics['vulnerabilities_detected_windows_online']))
        tm.add_metric(['vulnerabilities_detected_windows_offline'], int(ds_metrics['vulnerabilities_detected_windows_offline']))
        tm.add_metric(['vulnerabilities_protected_windows_online'], int(ds_metrics['vulnerabilities_protected_windows_online']))
        tm.add_metric(['vulnerabilities_protected_windows_offline'], int(ds_metrics['vulnerabilities_protected_windows_offline']))
        tm.add_metric(['vulnerabilities_exposed_windows'], int(ds_metrics['vulnerabilities_detected_windows'] - int(ds_metrics['vulnerabilities_protected_windows'])))
        tm.add_metric(['vulnerabilities_detected_linux'], int(ds_metrics['vulnerabilities_detected_linux']))
        tm.add_metric(['vulnerabilities_protected_linux'], int(ds_metrics['vulnerabilities_protected_linux']))
        tm.add_metric(['vulnerabilities_detected_linux_online'], int(ds_metrics['vulnerabilities_detected_linux_online']))
        tm.add_metric(['vulnerabilities_detected_linux_offline'], int(ds_metrics['vulnerabilities_detected_linux_offline']))
        tm.add_metric(['vulnerabilities_protected_linux_online'], int(ds_metrics['vulnerabilities_protected_linux_online']))
        tm.add_metric(['vulnerabilities_protected_linux_offline'], int(ds_metrics['vulnerabilities_protected_linux_offline']))
        tm.add_metric(['vulnerabilities_exposed_linux'], int(ds_metrics['vulnerabilities_detected_linux'] - int(ds_metrics['vulnerabilities_protected_linux'])))
        tm.add_metric(['vulnerabilities_detected_unknown'], int(ds_metrics['vulnerabilities_detected_unknown']))
        tm.add_metric(['vulnerabilities_protected_unknown'], int(ds_metrics['vulnerabilities_protected_unknown']))
        tm.add_metric(['vulnerabilities_detected_unknown_online'], int(ds_metrics['vulnerabilities_detected_unknown_online']))
        tm.add_metric(['vulnerabilities_detected_unknown_offline'], int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        tm.add_metric(['vulnerabilities_protected_unknown_online'], int(ds_metrics['vulnerabilities_protected_unknown_online']))
        tm.add_metric(['vulnerabilities_protected_unknown_offline'], int(ds_metrics['vulnerabilities_protected_unknown_offline']))
        tm.add_metric(['vulnerabilities_exposed_unknown'], int(ds_metrics['vulnerabilities_detected_unknown'] - int(ds_metrics['vulnerabilities_protected_unknown'])))
        yield tm

        
        # tm_hosts = CounterMetricFamily('deep_security_hosts', 'Deep Security Metrics', labels=['metric'])
        # tm_hosts.add_metric(['total_hosts'], int(ds_metrics['total']))
        # tm_hosts.add_metric(['managed_hosts'], int(ds_metrics['managed_count']))
        # tm_hosts.add_metric(['unmanaged_hosts'], int(ds_metrics['total']) - int(ds_metrics['managed_count']))
        # yield tm_hosts

        # tm_mhosts = CounterMetricFamily('deep_security_managed_hosts', 'Deep Security Metrics', labels=['metric'])
        # tm_mhosts.add_metric(['managed_hosts_online'], int(ds_metrics['managed_online']))
        # tm_mhosts.add_metric(['managed_hosts_offline'], int(ds_metrics['managed_offline']))
        # yield tm_mhosts

        # tm_moshosts = CounterMetricFamily('deep_security_managed_hosts_os', 'Deep Security Metrics', labels=['metric'])
        # tm_moshosts.add_metric(['managed_hosts_linux'], int(ds_metrics['os_linux_managed']))
        # tm_moshosts.add_metric(['managed_hosts_windows'], int(ds_metrics['os_windows_managed']))
        # yield tm_moshosts

        # tm_umoshosts = CounterMetricFamily('deep_security_unmanaged_hosts_os', 'Deep Security Metrics', labels=['metric'])
        # tm_umoshosts.add_metric(['linux'], int(ds_metrics['os_linux_unmanaged']))
        # tm_umoshosts.add_metric(['windows'], int(ds_metrics['os_windows_unmanaged']))
        # yield tm_umoshosts

        # tm_mhosts = CounterMetricFamily('deep_security_managed_hosts_os_all', 'Deep Security Metrics', labels=['metric'])
        # tm_mhosts.add_metric(['managed_linux'], int(ds_metrics['os_linux_managed']))
        # tm_mhosts.add_metric(['managed_windows'], int(ds_metrics['os_windows_managed']))
        # tm_mhosts.add_metric(['unmanaged_linux'], int(ds_metrics['os_linux_unmanaged']))
        # tm_mhosts.add_metric(['unmanaged_windows'], int(ds_metrics['os_windows_unmanaged']))
        # yield tm_mhosts

        # tm_os = CounterMetricFamily('deep_security_os_hosts', 'Deep Security Metrics', labels=['metric'])       
        # tm_os.add_metric(['windows'], int(ds_metrics['os_windows']))
        # tm_os.add_metric(['linux'], int(ds_metrics['os_linux']))
        # tm_os.add_metric(['unknown'], int(ds_metrics['os_unknown']))
        # yield tm_os

        # tm_modules = CounterMetricFamily('deep_security_modules', 'Deep Security Metrics', labels=['metric'])
        # tm_modules.add_metric(['antimalware_clients'], int(ds_metrics['am_count']))
        # tm_modules.add_metric(['web_reputation_clients'], int(ds_metrics['wr_count']))
        # tm_modules.add_metric(['firewall_clients'], int(ds_metrics['fw_count']))
        # tm_modules.add_metric(['ips_clients'], int(ds_metrics['ip_count']))
        # tm_modules.add_metric(['integrity_monitoring_clients'], int(ds_metrics['im_count']))
        # tm_modules.add_metric(['log_inspection_clients'], int(ds_metrics['li_count']))
        # yield tm_modules

        # tm_vul = CounterMetricFamily('deep_security_vulnerabilities_protection', 'Deep Security Metrics', labels=['metric'])
        # tm_vul.add_metric(['detected'], int(ds_metrics['vulnerabilities_detected']))
        # tm_vul.add_metric(['protected'], int(ds_metrics['vulnerabilities_protected']))
        # tm_vul.add_metric(['exposed'], int(ds_metrics['vulnerabilities_detected'] - int(ds_metrics['vulnerabilities_protected'])))
        # tm_vul.add_metric(['protected_inline'], int(ds_metrics['vulnerabilities_protected_inline']))
        # tm_vul.add_metric(['protected_tap'], int(ds_metrics['vulnerabilities_protected_tap']))
        # yield tm_vul

        # tm_vul_win = CounterMetricFamily('deep_security_vulnerabilities_protection_windows', 'Deep Security Metrics', labels=['metric'])
        # tm_vul_win.add_metric(['detected'], int(ds_metrics['vulnerabilities_detected_windows']))
        # tm_vul_win.add_metric(['protected'], int(ds_metrics['vulnerabilities_protected_windows']))
        # tm_vul_win.add_metric(['detected_online'], int(ds_metrics['vulnerabilities_detected_windows_online']))
        # tm_vul_win.add_metric(['detected_offline'], int(ds_metrics['vulnerabilities_detected_windows_offline']))
        # tm_vul_win.add_metric(['protected_online'], int(ds_metrics['vulnerabilities_protected_windows_online']))
        # tm_vul_win.add_metric(['protected_offline'], int(ds_metrics['vulnerabilities_protected_windows_offline']))
        # tm_vul_win.add_metric(['exposed'], int(ds_metrics['vulnerabilities_detected_windows'] - int(ds_metrics['vulnerabilities_protected_windows'])))
        # yield tm_vul_win

        # tm_vul_linux = CounterMetricFamily('deep_security_vulnerabilities_protection_linux', 'Deep Security Metrics', labels=['metric'])
        # tm_vul_linux.add_metric(['detected'], int(ds_metrics['vulnerabilities_detected_linux']))
        # tm_vul_linux.add_metric(['protected'], int(ds_metrics['vulnerabilities_protected_linux']))
        # tm_vul_linux.add_metric(['detected_online'], int(ds_metrics['vulnerabilities_detected_linux_online']))
        # tm_vul_linux.add_metric(['detected_offline'], int(ds_metrics['vulnerabilities_detected_linux_offline']))
        # tm_vul_linux.add_metric(['protected_online'], int(ds_metrics['vulnerabilities_protected_linux_online']))
        # tm_vul_linux.add_metric(['protected_offline'], int(ds_metrics['vulnerabilities_protected_linux_offline']))
        # tm_vul_linux.add_metric(['exposed'], int(ds_metrics['vulnerabilities_detected_linux'] - int(ds_metrics['vulnerabilities_protected_linux'])))
        # yield tm_vul_linux

        # tm_vul_unknown = CounterMetricFamily('deep_security_vulnerabilities_protection_unknown', 'Deep Security Metrics', labels=['metric'])
        # tm_vul_unknown.add_metric(['detected'], int(ds_metrics['vulnerabilities_detected_unknown']))
        # tm_vul_unknown.add_metric(['protected'], int(ds_metrics['vulnerabilities_protected_unknown']))
        # tm_vul_unknown.add_metric(['detected_online'], int(ds_metrics['vulnerabilities_detected_unknown_online']))
        # tm_vul_unknown.add_metric(['detected_offline'], int(ds_metrics['vulnerabilities_detected_unknown_offline']))
        # tm_vul_unknown.add_metric(['protected_online'], int(ds_metrics['vulnerabilities_protected_unknown_online']))
        # tm_vul_unknown.add_metric(['protected_offline'], int(ds_metrics['vulnerabilities_protected_unknown_offline']))
        # tm_vul_unknown.add_metric(['exposed'], int(ds_metrics['vulnerabilities_detected_unknown'] - int(ds_metrics['vulnerabilities_protected_unknown'])))
        # yield tm_vul_unknown

def shutdown_app(signal_number, frame):
    """
    this function will process the term signal that will sent by k8s
    """
    try:
        logging.info('we received signal {}. we are shutting now!'.format(signal_number))
        sys.exit(0)
    except Exception as e:
        logging.info('error to shut down app: {}'.format(e))


def main():
    signal.signal(signal.SIGTERM, shutdown_app)
    signal.signal(signal.SIGINT, shutdown_app)
    # signal.signal(signal.SIGHUP, reload_app)
    start_http_server(server_port)
    while True:
        time.sleep(sleep)


if __name__ == '__main__':
    ds_collector = CustomCollector()
    REGISTRY.register(ds_collector)
    main()

