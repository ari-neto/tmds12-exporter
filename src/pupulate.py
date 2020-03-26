from __future__ import print_function
import sys, warnings
import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint
import config


# Setup
if not sys.warnoptions:
	warnings.simplefilter("ignore")
configuration = deepsecurity.Configuration()
configuration.host = 'https://34.237.0.228:4119/api'

# Authentication
configuration.api_key['api-secret-key'] = config.DS_API_KEY

# Initialization
# Set Any Required Values
api_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
computer = deepsecurity.Computer()
api_version = 'YOUR VERSION'
expand_options = deepsecurity.Expand()
expand_options.add(expand_options.none)
expand = expand_options.list()
overrides = False

try:
	api_response = api_instance.create_computer(computer, api_version, expand=expand, overrides=overrides)
	pprint(api_response)
except ApiException as e:
	print("An exception occurred when calling ComputersApi.create_computer: %s\n" % e)

