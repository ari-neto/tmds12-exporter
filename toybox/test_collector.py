import time,random
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY
from prometheus_client import start_http_server

# https://github.com/RobustPerception/python_examples/blob/master/jenkins_exporter/jenkins_exporter.py
class DeepSecurityCollector(object):
    def collect(self):

        # statuses = ["lastBuild", "lastCompletedBuild", "lastFailedBuild",
        #     "lastStableBuild", "lastSuccessfulBuild", "lastUnstableBuild",
        #     "lastUnsuccessfulBuild"]

        # # The metrics we want to export.
        # metrics = {}
        # for s in statuses:
        #     snake_case = re.sub('([A-Z])', '_\\1', s).lower()
        #     metrics[s] = {
        #         'number':
        #             GaugeMetricFamily('jenkins_job_{0}'.format(snake_case),
        #                 'Jenkins build number for {0}'.format(s), labels=["jobname"]),
        #         'duration':
        #             GaugeMetricFamily('jenkins_job_{0}_duration_seconds'.format(snake_case),
        #                 'Jenkins build duration in seconds for {0}'.format(s), labels=["jobname"]),
        #         'timestamp':
        #             GaugeMetricFamily('jenkins_job_{0}_timestamp_seconds'.format(snake_case),
        #                 'Jenkins build timestamp in unixtime for {0}'.format(s), labels=["jobname"]),
        #         }

        #GaugeMetricFamily creates a Gauge and specifies labels, add_metric which adds a sample and then the yield to return the metric.
        c = GaugeMetricFamily(name='my_counter_total', value=None ,documentation='Help text', labels=['owner','project_name'],unit='')
        # Add 
        # any given combination of labels for the same metric name identifies a particular dimensional instantiation of that metric
        c.add_metric(['kaz','teste1'], random.random())
        c.add_metric(['kaz','teste2'], random.random())
        c.add_metric(['snake',''], 3.8)
        c.add_metric(labels=[],value=20,timestamp=None) 
        yield c

        g = GaugeMetricFamily("memory_usage", 'Help text', labels=['instance'])
        g.add_metric(["instance01.us.west.local"], 20)
        yield g

        c = CounterMetricFamily("http_request", 'Help text', labels=['app'])
        c.add_metric(["example"], 2000)
        yield c

if __name__ == '__main__':
    start_http_server(8000)
    REGISTRY.register(DeepSecurityCollector())
    while True:
        time.sleep(1)