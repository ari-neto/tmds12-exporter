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


class Action(object):
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
        'type': 'str',
        'status': 'str',
        'submitted_time': 'int',
        'id': 'int'
    }

    attribute_map = {
        'type': 'type',
        'status': 'status',
        'submitted_time': 'submittedTime',
        'id': 'ID'
    }

    def __init__(self, type=None, status=None, submitted_time=None, id=None):  # noqa: E501
        """Action - a model defined in Swagger"""  # noqa: E501

        self._type = None
        self._status = None
        self._submitted_time = None
        self._id = None
        self.discriminator = None

        if type is not None:
            self.type = type
        if status is not None:
            self.status = status
        if submitted_time is not None:
            self.submitted_time = submitted_time
        if id is not None:
            self.id = id

    @property
    def type(self):
        """Gets the type of this Action.  # noqa: E501

        Type of the GCPConnectorAction.  # noqa: E501

        :return: The type of this Action.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this Action.

        Type of the GCPConnectorAction.  # noqa: E501

        :param type: The type of this Action.  # noqa: E501
        :type: str
        """

        self._type = type

    @property
    def status(self):
        """Gets the status of this Action.  # noqa: E501

        Status of the GCPConnectorAction.  # noqa: E501

        :return: The status of this Action.  # noqa: E501
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """Sets the status of this Action.

        Status of the GCPConnectorAction.  # noqa: E501

        :param status: The status of this Action.  # noqa: E501
        :type: str
        """

        self._status = status

    @property
    def submitted_time(self):
        """Gets the submitted_time of this Action.  # noqa: E501

        Submitted time of the GCPConnectorAction.  # noqa: E501

        :return: The submitted_time of this Action.  # noqa: E501
        :rtype: int
        """
        return self._submitted_time

    @submitted_time.setter
    def submitted_time(self, submitted_time):
        """Sets the submitted_time of this Action.

        Submitted time of the GCPConnectorAction.  # noqa: E501

        :param submitted_time: The submitted_time of this Action.  # noqa: E501
        :type: int
        """

        self._submitted_time = submitted_time

    @property
    def id(self):
        """Gets the id of this Action.  # noqa: E501

        ID of the GCPConnectorAction.  # noqa: E501

        :return: The id of this Action.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this Action.

        ID of the GCPConnectorAction.  # noqa: E501

        :param id: The id of this Action.  # noqa: E501
        :type: int
        """

        self._id = id

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
        if issubclass(Action, dict):
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
        if not isinstance(other, Action):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

