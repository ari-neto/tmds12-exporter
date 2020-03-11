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


class TenantsApi(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    Ref: https://github.com/swagger-api/swagger-codegen
    """

    def __init__(self, api_client=None):
        if api_client is None:
            api_client = ApiClient()
        self.api_client = api_client

    def create_tenant(self, tenant, api_version, **kwargs):  # noqa: E501
        """Create a Tenant  # noqa: E501

        Create a new tenant.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_tenant(tenant, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Tenant tenant: The settings of the new tenant. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool bypass_tenant_cache: Indicates whether to bypass the tenant cache or not. Default value is false.
        :param bool confirmation_required: Indicates whether a confirmation email is required or not. Default value is true.
        :param bool asynchronous: Indicates whether it's an asynchronous call. Default value is false.
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.create_tenant_with_http_info(tenant, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.create_tenant_with_http_info(tenant, api_version, **kwargs)  # noqa: E501
            return data

    def create_tenant_with_http_info(self, tenant, api_version, **kwargs):  # noqa: E501
        """Create a Tenant  # noqa: E501

        Create a new tenant.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.create_tenant_with_http_info(tenant, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param Tenant tenant: The settings of the new tenant. (required)
        :param str api_version: The version of the api being called. (required)
        :param bool bypass_tenant_cache: Indicates whether to bypass the tenant cache or not. Default value is false.
        :param bool confirmation_required: Indicates whether a confirmation email is required or not. Default value is true.
        :param bool asynchronous: Indicates whether it's an asynchronous call. Default value is false.
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['tenant', 'api_version', 'bypass_tenant_cache', 'confirmation_required', 'asynchronous']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method create_tenant" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'tenant' is set
        if ('tenant' not in params or
                params['tenant'] is None):
            raise ValueError("Missing the required parameter `tenant` when calling `create_tenant`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `create_tenant`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []
        if 'bypass_tenant_cache' in params:
            query_params.append(('bypassTenantCache', params['bypass_tenant_cache']))  # noqa: E501
        if 'confirmation_required' in params:
            query_params.append(('confirmationRequired', params['confirmation_required']))  # noqa: E501
        if 'asynchronous' in params:
            query_params.append(('asynchronous', params['asynchronous']))  # noqa: E501

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'tenant' in params:
            body_params = params['tenant']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/tenants', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Tenant',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def delete_tenant(self, tenant_id, api_version, **kwargs):  # noqa: E501
        """Delete a Tenant  # noqa: E501

        Delete a tenant by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_tenant(tenant_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.delete_tenant_with_http_info(tenant_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.delete_tenant_with_http_info(tenant_id, api_version, **kwargs)  # noqa: E501
            return data

    def delete_tenant_with_http_info(self, tenant_id, api_version, **kwargs):  # noqa: E501
        """Delete a Tenant  # noqa: E501

        Delete a tenant by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.delete_tenant_with_http_info(tenant_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to delete. (required)
        :param str api_version: The version of the api being called. (required)
        :return: None
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['tenant_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method delete_tenant" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'tenant_id' is set
        if ('tenant_id' not in params or
                params['tenant_id'] is None):
            raise ValueError("Missing the required parameter `tenant_id` when calling `delete_tenant`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `delete_tenant`")  # noqa: E501

        if 'tenant_id' in params and not re.search('\\d+', str(params['tenant_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `tenant_id` when calling `delete_tenant`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'tenant_id' in params:
            path_params['tenantID'] = params['tenant_id']  # noqa: E501

        query_params = []

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
            '/tenants/{tenantID}', 'DELETE',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type=None,  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def describe_tenant(self, tenant_id, api_version, **kwargs):  # noqa: E501
        """Describe a Tenant  # noqa: E501

        Describe a tenant by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_tenant(tenant_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.describe_tenant_with_http_info(tenant_id, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.describe_tenant_with_http_info(tenant_id, api_version, **kwargs)  # noqa: E501
            return data

    def describe_tenant_with_http_info(self, tenant_id, api_version, **kwargs):  # noqa: E501
        """Describe a Tenant  # noqa: E501

        Describe a tenant by ID.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.describe_tenant_with_http_info(tenant_id, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to describe. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['tenant_id', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method describe_tenant" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'tenant_id' is set
        if ('tenant_id' not in params or
                params['tenant_id'] is None):
            raise ValueError("Missing the required parameter `tenant_id` when calling `describe_tenant`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `describe_tenant`")  # noqa: E501

        if 'tenant_id' in params and not re.search('\\d+', str(params['tenant_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `tenant_id` when calling `describe_tenant`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'tenant_id' in params:
            path_params['tenantID'] = params['tenant_id']  # noqa: E501

        query_params = []

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
            '/tenants/{tenantID}', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Tenant',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def generate_tenant_api_secret_key(self, tenant_id, api_key, api_version, **kwargs):  # noqa: E501
        """Generate an API Key for the Tenant  # noqa: E501

        Generate a new API key for a tenant from the primary account. This key will be expired after 6 hours if no expiryDate set.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.generate_tenant_api_secret_key(tenant_id, api_key, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant the key is being generated for. (required)
        :param ApiKey api_key: The settings of the new API key. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApiKey
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.generate_tenant_api_secret_key_with_http_info(tenant_id, api_key, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.generate_tenant_api_secret_key_with_http_info(tenant_id, api_key, api_version, **kwargs)  # noqa: E501
            return data

    def generate_tenant_api_secret_key_with_http_info(self, tenant_id, api_key, api_version, **kwargs):  # noqa: E501
        """Generate an API Key for the Tenant  # noqa: E501

        Generate a new API key for a tenant from the primary account. This key will be expired after 6 hours if no expiryDate set.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.generate_tenant_api_secret_key_with_http_info(tenant_id, api_key, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant the key is being generated for. (required)
        :param ApiKey api_key: The settings of the new API key. (required)
        :param str api_version: The version of the api being called. (required)
        :return: ApiKey
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['tenant_id', 'api_key', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method generate_tenant_api_secret_key" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'tenant_id' is set
        if ('tenant_id' not in params or
                params['tenant_id'] is None):
            raise ValueError("Missing the required parameter `tenant_id` when calling `generate_tenant_api_secret_key`")  # noqa: E501
        # verify the required parameter 'api_key' is set
        if ('api_key' not in params or
                params['api_key'] is None):
            raise ValueError("Missing the required parameter `api_key` when calling `generate_tenant_api_secret_key`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `generate_tenant_api_secret_key`")  # noqa: E501

        if 'tenant_id' in params and not re.search('\\d+', str(params['tenant_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `tenant_id` when calling `generate_tenant_api_secret_key`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'tenant_id' in params:
            path_params['tenantID'] = params['tenant_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'api_key' in params:
            body_params = params['api_key']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/tenants/{tenantID}/apikeys', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='ApiKey',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def list_tenants(self, api_version, **kwargs):  # noqa: E501
        """List Tenants  # noqa: E501

        Lists all tenants.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_tenants(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Tenants
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.list_tenants_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.list_tenants_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def list_tenants_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """List Tenants  # noqa: E501

        Lists all tenants.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.list_tenants_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :return: Tenants
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method list_tenants" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `list_tenants`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

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
            '/tenants', 'GET',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Tenants',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def modify_tenant(self, tenant_id, tenant, api_version, **kwargs):  # noqa: E501
        """Modify a Tenant  # noqa: E501

        Modify a tenant by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_tenant(tenant_id, tenant, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to modify. (required)
        :param Tenant tenant: The settings of the tenant to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.modify_tenant_with_http_info(tenant_id, tenant, api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.modify_tenant_with_http_info(tenant_id, tenant, api_version, **kwargs)  # noqa: E501
            return data

    def modify_tenant_with_http_info(self, tenant_id, tenant, api_version, **kwargs):  # noqa: E501
        """Modify a Tenant  # noqa: E501

        Modify a tenant by ID. Any unset elements will be left unchanged.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.modify_tenant_with_http_info(tenant_id, tenant, api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param int tenant_id: The ID number of the tenant to modify. (required)
        :param Tenant tenant: The settings of the tenant to modify. (required)
        :param str api_version: The version of the api being called. (required)
        :return: Tenant
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['tenant_id', 'tenant', 'api_version']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method modify_tenant" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'tenant_id' is set
        if ('tenant_id' not in params or
                params['tenant_id'] is None):
            raise ValueError("Missing the required parameter `tenant_id` when calling `modify_tenant`")  # noqa: E501
        # verify the required parameter 'tenant' is set
        if ('tenant' not in params or
                params['tenant'] is None):
            raise ValueError("Missing the required parameter `tenant` when calling `modify_tenant`")  # noqa: E501
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `modify_tenant`")  # noqa: E501

        if 'tenant_id' in params and not re.search('\\d+', str(params['tenant_id'])):  # noqa: E501
            raise ValueError("Invalid value for parameter `tenant_id` when calling `modify_tenant`, must conform to the pattern `/\\d+/`")  # noqa: E501
        collection_formats = {}

        path_params = {}
        if 'tenant_id' in params:
            path_params['tenantID'] = params['tenant_id']  # noqa: E501

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'tenant' in params:
            body_params = params['tenant']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/tenants/{tenantID}', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Tenant',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)

    def search_tenants(self, api_version, **kwargs):  # noqa: E501
        """Search Tenants  # noqa: E501

        Search for tenants using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_tenants(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: Tenants
                 If the method is called asynchronously,
                 returns the request thread.
        """
        kwargs['_return_http_data_only'] = True
        if kwargs.get('async_req'):
            return self.search_tenants_with_http_info(api_version, **kwargs)  # noqa: E501
        else:
            (data) = self.search_tenants_with_http_info(api_version, **kwargs)  # noqa: E501
            return data

    def search_tenants_with_http_info(self, api_version, **kwargs):  # noqa: E501
        """Search Tenants  # noqa: E501

        Search for tenants using optional filters.  # noqa: E501
        This method makes a synchronous HTTP request by default. To make an
        asynchronous HTTP request, please pass async_req=True
        >>> thread = api.search_tenants_with_http_info(api_version, async_req=True)
        >>> result = thread.get()

        :param async_req bool
        :param str api_version: The version of the api being called. (required)
        :param SearchFilter search_filter: A collection of options used to filter the search results.
        :return: Tenants
                 If the method is called asynchronously,
                 returns the request thread.
        """

        all_params = ['api_version', 'search_filter']  # noqa: E501
        all_params.append('async_req')
        all_params.append('_return_http_data_only')
        all_params.append('_preload_content')
        all_params.append('_request_timeout')

        params = locals()
        for key, val in six.iteritems(params['kwargs']):
            if key not in all_params:
                raise TypeError(
                    "Got an unexpected keyword argument '%s'"
                    " to method search_tenants" % key
                )
            params[key] = val
        del params['kwargs']
        # verify the required parameter 'api_version' is set
        if ('api_version' not in params or
                params['api_version'] is None):
            raise ValueError("Missing the required parameter `api_version` when calling `search_tenants`")  # noqa: E501

        collection_formats = {}

        path_params = {}

        query_params = []

        header_params = {}
        if 'api_version' in params:
            header_params['api-version'] = params['api_version']  # noqa: E501

        form_params = []
        local_var_files = {}

        body_params = None
        if 'search_filter' in params:
            body_params = params['search_filter']
        # HTTP header `Accept`
        header_params['Accept'] = self.api_client.select_header_accept(
            ['application/json'])  # noqa: E501

        # HTTP header `Content-Type`
        header_params['Content-Type'] = self.api_client.select_header_content_type(  # noqa: E501
            ['application/json'])  # noqa: E501

        # Authentication setting
        auth_settings = ['DefaultAuthentication']  # noqa: E501

        return self.api_client.call_api(
            '/tenants/search', 'POST',
            path_params,
            query_params,
            header_params,
            body=body_params,
            post_params=form_params,
            files=local_var_files,
            response_type='Tenants',  # noqa: E501
            auth_settings=auth_settings,
            async_req=params.get('async_req'),
            _return_http_data_only=params.get('_return_http_data_only'),
            _preload_content=params.get('_preload_content', True),
            _request_timeout=params.get('_request_timeout'),
            collection_formats=collection_formats)
