# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2019 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.349
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


from __future__ import absolute_import

import re  # noqa: F401

# python 2 and python 3 compatibility library
import six

from deepsecurity.api_client import ApiClient


class ComputerFirewallRuleAssignmentsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def add_firewall_rule_ids_to_computer(self, computer_id, firewall_rule_ids, api_version, **kwargs):  # noqa: E501
        """Add Firewall Rule IDs  # noqa: E501

        Assign firewall rule IDs to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_firewall_rule_ids_to_computer(computer_id, firewall_rule_ids, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param RuleIDs firewall_rule_ids: The ID numbers of the firewall rules to add. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.add_firewall_rule_ids_to_computer_with_http_info(computer_id, firewall_rule_ids, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.add_firewall_rule_ids_to_computer_with_http_info(computer_id, firewall_rule_ids, api_version, **kwargs)  # noqa: E501
            return data

    def add_firewall_rule_ids_to_computer_with_http_info(self, computer_id, firewall_rule_ids, api_version, **kwargs):  # noqa: E501
        """Add Firewall Rule IDs  # noqa: E501

        Assign firewall rule IDs to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.add_firewall_rule_ids_to_computer_with_http_info(computer_id, firewall_rule_ids, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param RuleIDs firewall_rule_ids: The ID numbers of the firewall rules to add. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'firewall_rule_ids', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method add_firewall_rule_ids_to_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `add_firewall_rule_ids_to_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule_ids' is set
        if ('firewall_rule_ids' not in params or
                params['firewall_rule_ids'] is None):
            raise ValueError("Missing the required parameter `firewall_rule_ids` when calling `add_firewall_rule_ids_to_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `add_firewall_rule_ids_to_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', str(params['computer_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `add_firewall_rule_ids_to_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'firewall_rule_ids' in params:
            body_params = params['firewall_rule_ids']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/assignments', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallAssignments',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_firewall_rule_ids_on_computer(self, computer_id, api_version, **kwargs):  # noqa: E501
        """List Firewall Rule IDs  # noqa: E501

        Lists all firewall rule IDs assigned to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_firewall_rule_ids_on_computer(computer_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
            return data

    def list_firewall_rule_ids_on_computer_with_http_info(self, computer_id, api_version, **kwargs):  # noqa: E501
        """List Firewall Rule IDs  # noqa: E501

        Lists all firewall rule IDs assigned to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_firewall_rule_ids_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `list_firewall_rule_ids_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_firewall_rule_ids_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', str(params['computer_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `list_firewall_rule_ids_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/assignments', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallAssignments',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def remove_firewall_rule_id_from_computer(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Remove a Firewall Rule ID  # noqa: E501

        Unassign a firewall rule ID from a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.remove_firewall_rule_id_from_computer(computer_id, firewall_rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.remove_firewall_rule_id_from_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.remove_firewall_rule_id_from_computer_with_http_info(computer_id, firewall_rule_id, api_version, **kwargs)  # noqa: E501
            return data

    def remove_firewall_rule_id_from_computer_with_http_info(self, computer_id, firewall_rule_id, api_version, **kwargs):  # noqa: E501
        """Remove a Firewall Rule ID  # noqa: E501

        Unassign a firewall rule ID from a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.remove_firewall_rule_id_from_computer_with_http_info(computer_id, firewall_rule_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param int firewall_rule_id: The ID number of the firewall rule to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'firewall_rule_id', 'api_version', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method remove_firewall_rule_id_from_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `remove_firewall_rule_id_from_computer`")  # noqa: E501
        # verify the required parameter 'firewall_rule_id' is set
        if ('firewall_rule_id' not in params or
                params['firewall_rule_id'] is None):
            raise ValueError("Missing the required parameter `firewall_rule_id` when calling `remove_firewall_rule_id_from_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `remove_firewall_rule_id_from_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', str(params['computer_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `remove_firewall_rule_id_from_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        if 'firewall_rule_id' in params and not re.search('\\d+', str(params['firewall_rule_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `firewall_rule_id` when calling `remove_firewall_rule_id_from_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501
        if 'firewall_rule_id' in params:
            path_params['firewallRuleID'] = params['firewall_rule_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/assignments/{firewallRuleID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallAssignments',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def set_firewall_rule_ids_on_computer(self, computer_id, api_version, **kwargs):  # noqa: E501
        """Set Firewall Rule IDs  # noqa: E501

        Set firewall rule IDs assigned to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.set_firewall_rule_ids_on_computer(computer_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param RuleIDs firewall_rule_ids: The ID numbers of the firewall rules to set.
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.set_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.set_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, **kwargs)  # noqa: E501
            return data

    def set_firewall_rule_ids_on_computer_with_http_info(self, computer_id, api_version, **kwargs):  # noqa: E501
        """Set Firewall Rule IDs  # noqa: E501

        Set firewall rule IDs assigned to a computer.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.set_firewall_rule_ids_on_computer_with_http_info(computer_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int computer_id: The ID number of the computer. (required)
        :param str api_version: The version of the api being called. (required)
        :param RuleIDs firewall_rule_ids: The ID numbers of the firewall rules to set.
        :param bool overrides: Return only rule IDs assigned directly to the current computer.
        :return: FirewallAssignments
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['computer_id', 'api_version', 'firewall_rule_ids', 'overrides']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method set_firewall_rule_ids_on_computer" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'computer_id' is set
        if ('computer_id' not in params or
                params['computer_id'] is None):
            raise ValueError("Missing the required parameter `computer_id` when calling `set_firewall_rule_ids_on_computer`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `set_firewall_rule_ids_on_computer`")  # noqa: E501

        if 'computer_id' in params and not re.search('\\d+', str(params['computer_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `computer_id` when calling `set_firewall_rule_ids_on_computer`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'computer_id' in params:
            path_params['computerID'] = params['computer_id']  # noqa: E501

        query_params = []
        if 'overrides' in params:
            query_params.append(('overrides', params['overrides']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'firewall_rule_ids' in params:
            body_params = params['firewall_rule_ids']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/computers/{computerID}/firewall/assignments', 'PUT',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='FirewallAssignments',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
