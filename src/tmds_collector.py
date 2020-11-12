import time
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from prometheus_client import start_http_server

class DeepSecurityCollector(object):
    def collect(self):
        pass

if __name__ == '__main__':
    start_http_server(8000)
    REGISTRY.register(DeepSecurityCollector())
    while True:
        time.sleep(1)