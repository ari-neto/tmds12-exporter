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

from deepsecurity.models.application_control_global_rule import ApplicationControlGlobalRule  # noqa: F401,E501


class ApplicationControlGlobalRules(object):
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
        'application_control_global_rules': 'list[ApplicationControlGlobalRule]'
    }

    attribute_map = {
        'application_control_global_rules': 'applicationControlGlobalRules'
    }

    def __init__(self, application_control_global_rules=None):  # noqa: E501
        """ApplicationControlGlobalRules - a model defined in Swagger"""  # noqa: E501

        self._application_control_global_rules = None
        self.discriminator = None

        if application_control_global_rules is not None:
            self.application_control_global_rules = application_control_global_rules

    @property
    def application_control_global_rules(self):
        """Gets the application_control_global_rules of this ApplicationControlGlobalRules.  # noqa: E501


        :return: The application_control_global_rules of this ApplicationControlGlobalRules.  # noqa: E501
        :rtype: list[ApplicationControlGlobalRule]
        """
        return self._application_control_global_rules

    @application_control_global_rules.setter
    def application_control_global_rules(self, application_control_global_rules):
        """Sets the application_control_global_rules of this ApplicationControlGlobalRules.


        :param application_control_global_rules: The application_control_global_rules of this ApplicationControlGlobalRules.  # noqa: E501
        :type: list[ApplicationControlGlobalRule]
        """

        self._application_control_global_rules = application_control_global_rules

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
        if issubclass(ApplicationControlGlobalRules, dict):
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
        if not isinstance(other, ApplicationControlGlobalRules):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

