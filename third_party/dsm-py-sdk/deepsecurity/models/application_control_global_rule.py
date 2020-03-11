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


class ApplicationControlGlobalRule(object):
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
        'sha256': 'str',
        'description': 'str',
        'action': 'str',
        'last_updated_administrator': 'int',
        'last_updated': 'int',
        'id': 'int'
    }

    attribute_map = {
        'sha256': 'sha256',
        'description': 'description',
        'action': 'action',
        'last_updated_administrator': 'lastUpdatedAdministrator',
        'last_updated': 'lastUpdated',
        'id': 'ID'
    }

    def __init__(self, sha256=None, description=None, action=None, last_updated_administrator=None, last_updated=None, id=None):  # noqa: E501
        """ApplicationControlGlobalRule - a model defined in Swagger"""  # noqa: E501

        self._sha256 = None
        self._description = None
        self._action = None
        self._last_updated_administrator = None
        self._last_updated = None
        self._id = None
        self.discriminator = None

        if sha256 is not None:
            self.sha256 = sha256
        if description is not None:
            self.description = description
        if action is not None:
            self.action = action
        if last_updated_administrator is not None:
            self.last_updated_administrator = last_updated_administrator
        if last_updated is not None:
            self.last_updated = last_updated
        if id is not None:
            self.id = id

    @property
    def sha256(self):
        """Gets the sha256 of this ApplicationControlGlobalRule.  # noqa: E501

        SHA-256 hash of the executable named in the rule. Searchable as String.  # noqa: E501

        :return: The sha256 of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: str
        """
        return self._sha256

    @sha256.setter
    def sha256(self, sha256):
        """Sets the sha256 of this ApplicationControlGlobalRule.

        SHA-256 hash of the executable named in the rule. Searchable as String.  # noqa: E501

        :param sha256: The sha256 of this ApplicationControlGlobalRule.  # noqa: E501
        :type: str
        """

        self._sha256 = sha256

    @property
    def description(self):
        """Gets the description of this ApplicationControlGlobalRule.  # noqa: E501

        Description of the rule. Searchable as String.  # noqa: E501

        :return: The description of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this ApplicationControlGlobalRule.

        Description of the rule. Searchable as String.  # noqa: E501

        :param description: The description of this ApplicationControlGlobalRule.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def action(self):
        """Gets the action of this ApplicationControlGlobalRule.  # noqa: E501

        Action to take when a user attempts to launch the executable named in the rule. Searchable as Choice.  # noqa: E501

        :return: The action of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: str
        """
        return self._action

    @action.setter
    def action(self, action):
        """Sets the action of this ApplicationControlGlobalRule.

        Action to take when a user attempts to launch the executable named in the rule. Searchable as Choice.  # noqa: E501

        :param action: The action of this ApplicationControlGlobalRule.  # noqa: E501
        :type: str
        """
        allowed_values = ["block"]  # noqa: E501
        if action not in allowed_values:
            raise ValueError(
                "Invalid value for `action` ({0}), must be one of {1}"  # noqa: E501
                .format(action, allowed_values)
            )

        self._action = action

    @property
    def last_updated_administrator(self):
        """Gets the last_updated_administrator of this ApplicationControlGlobalRule.  # noqa: E501

        ID of the last administrator to update the rule. Searchable as Numeric.  # noqa: E501

        :return: The last_updated_administrator of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: int
        """
        return self._last_updated_administrator

    @last_updated_administrator.setter
    def last_updated_administrator(self, last_updated_administrator):
        """Sets the last_updated_administrator of this ApplicationControlGlobalRule.

        ID of the last administrator to update the rule. Searchable as Numeric.  # noqa: E501

        :param last_updated_administrator: The last_updated_administrator of this ApplicationControlGlobalRule.  # noqa: E501
        :type: int
        """

        self._last_updated_administrator = last_updated_administrator

    @property
    def last_updated(self):
        """Gets the last_updated of this ApplicationControlGlobalRule.  # noqa: E501

        Timestamp of the last rule modification, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The last_updated of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: int
        """
        return self._last_updated

    @last_updated.setter
    def last_updated(self, last_updated):
        """Sets the last_updated of this ApplicationControlGlobalRule.

        Timestamp of the last rule modification, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param last_updated: The last_updated of this ApplicationControlGlobalRule.  # noqa: E501
        :type: int
        """

        self._last_updated = last_updated

    @property
    def id(self):
        """Gets the id of this ApplicationControlGlobalRule.  # noqa: E501

        ID of the application control rule. Searchable as ID.  # noqa: E501

        :return: The id of this ApplicationControlGlobalRule.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this ApplicationControlGlobalRule.

        ID of the application control rule. Searchable as ID.  # noqa: E501

        :param id: The id of this ApplicationControlGlobalRule.  # noqa: E501
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
        if issubclass(ApplicationControlGlobalRule, dict):
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
        if not isinstance(other, ApplicationControlGlobalRule):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

