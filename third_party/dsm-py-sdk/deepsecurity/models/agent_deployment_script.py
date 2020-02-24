# coding: utf-8

"""
    Trend Micro Deep Security API

    Copyright 2018 - 2019 Trend Micro Incorporated.<br/>Get protected, stay secured, and keep informed with Trend Micro Deep Security's new RESTful API. Access system data and manage security configurations to automate your security workflows and integrate Deep Security into your CI/CD pipeline.  # noqa: E501

    OpenAPI spec version: 12.5.349
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class AgentDeploymentScript(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'platform': 'str',
        'validate_certificate_required': 'bool',
        'activation_required': 'bool',
        'dsm_proxy_id': 'int',
        'relay_proxy_id': 'int',
        'policy_id': 'int',
        'relay_group_id': 'int',
        'computer_group_id': 'int',
        'script_body': 'str'
    }

    attribute_map = {
        'platform': 'platform',
        'validate_certificate_required': 'validateCertificateRequired',
        'activation_required': 'activationRequired',
        'dsm_proxy_id': 'dsmProxyID',
        'relay_proxy_id': 'relayProxyID',
        'policy_id': 'policyID',
        'relay_group_id': 'relayGroupID',
        'computer_group_id': 'computerGroupID',
        'script_body': 'scriptBody'
    }

    def __init__(self, platform=None, validate_certificate_required=None, activation_required=None, dsm_proxy_id=None, relay_proxy_id=None, policy_id=None, relay_group_id=None, computer_group_id=None, script_body=None):  # noqa: E501
        """AgentDeploymentScript - a model defined in Swagger"""  # noqa: E501

        self._platform = None
        self._validate_certificate_required = None
        self._activation_required = None
        self._dsm_proxy_id = None
        self._relay_proxy_id = None
        self._policy_id = None
        self._relay_group_id = None
        self._computer_group_id = None
        self._script_body = None
        self.discriminator = None

        if platform is not None:
            self.platform = platform
        if validate_certificate_required is not None:
            self.validate_certificate_required = validate_certificate_required
        if activation_required is not None:
            self.activation_required = activation_required
        if dsm_proxy_id is not None:
            self.dsm_proxy_id = dsm_proxy_id
        if relay_proxy_id is not None:
            self.relay_proxy_id = relay_proxy_id
        if policy_id is not None:
            self.policy_id = policy_id
        if relay_group_id is not None:
            self.relay_group_id = relay_group_id
        if computer_group_id is not None:
            self.computer_group_id = computer_group_id
        if script_body is not None:
            self.script_body = script_body

    @property
    def platform(self):
        """Gets the platform of this AgentDeploymentScript.  # noqa: E501

        Platform type for agent deployment.  # noqa: E501

        :return: The platform of this AgentDeploymentScript.  # noqa: E501
        :rtype: str
        """
        return self._platform

    @platform.setter
    def platform(self, platform):
        """Sets the platform of this AgentDeploymentScript.

        Platform type for agent deployment.  # noqa: E501

        :param platform: The platform of this AgentDeploymentScript.  # noqa: E501
        :type: str
        """
        allowed_values = ["linux", "windows", "solaris", "aix"]  # noqa: E501
        if platform not in allowed_values:
            raise ValueError(
                "Invalid value for `platform` ({0}), must be one of {1}"  # noqa: E501
                .format(platform, allowed_values)
            )

        self._platform = platform

    @property
    def validate_certificate_required(self):
        """Gets the validate_certificate_required of this AgentDeploymentScript.  # noqa: E501

        Validate if Deep Security Manager is using a valid TLS certificate from a trusted certificate authority (CA) when downloading the agent software.  # noqa: E501

        :return: The validate_certificate_required of this AgentDeploymentScript.  # noqa: E501
        :rtype: bool
        """
        return self._validate_certificate_required

    @validate_certificate_required.setter
    def validate_certificate_required(self, validate_certificate_required):
        """Sets the validate_certificate_required of this AgentDeploymentScript.

        Validate if Deep Security Manager is using a valid TLS certificate from a trusted certificate authority (CA) when downloading the agent software.  # noqa: E501

        :param validate_certificate_required: The validate_certificate_required of this AgentDeploymentScript.  # noqa: E501
        :type: bool
        """

        self._validate_certificate_required = validate_certificate_required

    @property
    def activation_required(self):
        """Gets the activation_required of this AgentDeploymentScript.  # noqa: E501

        Activate the agent at startup.  # noqa: E501

        :return: The activation_required of this AgentDeploymentScript.  # noqa: E501
        :rtype: bool
        """
        return self._activation_required

    @activation_required.setter
    def activation_required(self, activation_required):
        """Sets the activation_required of this AgentDeploymentScript.

        Activate the agent at startup.  # noqa: E501

        :param activation_required: The activation_required of this AgentDeploymentScript.  # noqa: E501
        :type: bool
        """

        self._activation_required = activation_required

    @property
    def dsm_proxy_id(self):
        """Gets the dsm_proxy_id of this AgentDeploymentScript.  # noqa: E501

        ID of the proxy server for contacting Deep Security Manager.  # noqa: E501

        :return: The dsm_proxy_id of this AgentDeploymentScript.  # noqa: E501
        :rtype: int
        """
        return self._dsm_proxy_id

    @dsm_proxy_id.setter
    def dsm_proxy_id(self, dsm_proxy_id):
        """Sets the dsm_proxy_id of this AgentDeploymentScript.

        ID of the proxy server for contacting Deep Security Manager.  # noqa: E501

        :param dsm_proxy_id: The dsm_proxy_id of this AgentDeploymentScript.  # noqa: E501
        :type: int
        """

        self._dsm_proxy_id = dsm_proxy_id

    @property
    def relay_proxy_id(self):
        """Gets the relay_proxy_id of this AgentDeploymentScript.  # noqa: E501

        ID of the proxy server for contacting Relay(s).  # noqa: E501

        :return: The relay_proxy_id of this AgentDeploymentScript.  # noqa: E501
        :rtype: int
        """
        return self._relay_proxy_id

    @relay_proxy_id.setter
    def relay_proxy_id(self, relay_proxy_id):
        """Sets the relay_proxy_id of this AgentDeploymentScript.

        ID of the proxy server for contacting Relay(s).  # noqa: E501

        :param relay_proxy_id: The relay_proxy_id of this AgentDeploymentScript.  # noqa: E501
        :type: int
        """

        self._relay_proxy_id = relay_proxy_id

    @property
    def policy_id(self):
        """Gets the policy_id of this AgentDeploymentScript.  # noqa: E501

        ID of the policy assigned to the computer.  # noqa: E501

        :return: The policy_id of this AgentDeploymentScript.  # noqa: E501
        :rtype: int
        """
        return self._policy_id

    @policy_id.setter
    def policy_id(self, policy_id):
        """Sets the policy_id of this AgentDeploymentScript.

        ID of the policy assigned to the computer.  # noqa: E501

        :param policy_id: The policy_id of this AgentDeploymentScript.  # noqa: E501
        :type: int
        """

        self._policy_id = policy_id

    @property
    def relay_group_id(self):
        """Gets the relay_group_id of this AgentDeploymentScript.  # noqa: E501

        ID of the relay group to which the computer belongs.  # noqa: E501

        :return: The relay_group_id of this AgentDeploymentScript.  # noqa: E501
        :rtype: int
        """
        return self._relay_group_id

    @relay_group_id.setter
    def relay_group_id(self, relay_group_id):
        """Sets the relay_group_id of this AgentDeploymentScript.

        ID of the relay group to which the computer belongs.  # noqa: E501

        :param relay_group_id: The relay_group_id of this AgentDeploymentScript.  # noqa: E501
        :type: int
        """

        self._relay_group_id = relay_group_id

    @property
    def computer_group_id(self):
        """Gets the computer_group_id of this AgentDeploymentScript.  # noqa: E501

        ID of the computer group to which the computer belongs.  # noqa: E501

        :return: The computer_group_id of this AgentDeploymentScript.  # noqa: E501
        :rtype: int
        """
        return self._computer_group_id

    @computer_group_id.setter
    def computer_group_id(self, computer_group_id):
        """Sets the computer_group_id of this AgentDeploymentScript.

        ID of the computer group to which the computer belongs.  # noqa: E501

        :param computer_group_id: The computer_group_id of this AgentDeploymentScript.  # noqa: E501
        :type: int
        """

        self._computer_group_id = computer_group_id

    @property
    def script_body(self):
        """Gets the script_body of this AgentDeploymentScript.  # noqa: E501

        Agent deployment script.  # noqa: E501

        :return: The script_body of this AgentDeploymentScript.  # noqa: E501
        :rtype: str
        """
        return self._script_body

    @script_body.setter
    def script_body(self, script_body):
        """Sets the script_body of this AgentDeploymentScript.

        Agent deployment script.  # noqa: E501

        :param script_body: The script_body of this AgentDeploymentScript.  # noqa: E501
        :type: str
        """

        self._script_body = script_body

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(AgentDeploymentScript, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, AgentDeploymentScript):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

