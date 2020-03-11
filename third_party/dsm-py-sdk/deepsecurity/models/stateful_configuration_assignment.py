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


class StatefulConfigurationAssignment(object):
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
        'interface_id': 'int',
        'interface_type_id': 'int',
        'stateful_configuration_id': 'int'
    }

    attribute_map = {
        'interface_id': 'interfaceID',
        'interface_type_id': 'interfaceTypeID',
        'stateful_configuration_id': 'statefulConfigurationID'
    }

    def __init__(self, interface_id=None, interface_type_id=None, stateful_configuration_id=None):  # noqa: E501
        """StatefulConfigurationAssignment - a model defined in Swagger"""  # noqa: E501

        self._interface_id = None
        self._interface_type_id = None
        self._stateful_configuration_id = None
        self.discriminator = None

        if interface_id is not None:
            self.interface_id = interface_id
        if interface_type_id is not None:
            self.interface_type_id = interface_type_id
        if stateful_configuration_id is not None:
            self.stateful_configuration_id = stateful_configuration_id

    @property
    def interface_id(self):
        """Gets the interface_id of this StatefulConfigurationAssignment.  # noqa: E501

        ID of interface.  # noqa: E501

        :return: The interface_id of this StatefulConfigurationAssignment.  # noqa: E501
        :rtype: int
        """
        return self._interface_id

    @interface_id.setter
    def interface_id(self, interface_id):
        """Sets the interface_id of this StatefulConfigurationAssignment.

        ID of interface.  # noqa: E501

        :param interface_id: The interface_id of this StatefulConfigurationAssignment.  # noqa: E501
        :type: int
        """

        self._interface_id = interface_id

    @property
    def interface_type_id(self):
        """Gets the interface_type_id of this StatefulConfigurationAssignment.  # noqa: E501

        ID of interface type.  # noqa: E501

        :return: The interface_type_id of this StatefulConfigurationAssignment.  # noqa: E501
        :rtype: int
        """
        return self._interface_type_id

    @interface_type_id.setter
    def interface_type_id(self, interface_type_id):
        """Sets the interface_type_id of this StatefulConfigurationAssignment.

        ID of interface type.  # noqa: E501

        :param interface_type_id: The interface_type_id of this StatefulConfigurationAssignment.  # noqa: E501
        :type: int
        """

        self._interface_type_id = interface_type_id

    @property
    def stateful_configuration_id(self):
        """Gets the stateful_configuration_id of this StatefulConfigurationAssignment.  # noqa: E501

        ID of stateful configuration.  # noqa: E501

        :return: The stateful_configuration_id of this StatefulConfigurationAssignment.  # noqa: E501
        :rtype: int
        """
        return self._stateful_configuration_id

    @stateful_configuration_id.setter
    def stateful_configuration_id(self, stateful_configuration_id):
        """Sets the stateful_configuration_id of this StatefulConfigurationAssignment.

        ID of stateful configuration.  # noqa: E501

        :param stateful_configuration_id: The stateful_configuration_id of this StatefulConfigurationAssignment.  # noqa: E501
        :type: int
        """

        self._stateful_configuration_id = stateful_configuration_id

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
        if issubclass(StatefulConfigurationAssignment, dict):
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
        if not isinstance(other, StatefulConfigurationAssignment):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

