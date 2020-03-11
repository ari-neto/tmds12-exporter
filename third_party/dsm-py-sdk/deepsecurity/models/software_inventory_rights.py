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


class SoftwareInventoryRights(object):
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
        'can_create_new_software_inventory': 'bool',
        'can_delete_software_inventory': 'bool',
        'can_view_software_inventory': 'bool'
    }

    attribute_map = {
        'can_create_new_software_inventory': 'canCreateNewSoftwareInventory',
        'can_delete_software_inventory': 'canDeleteSoftwareInventory',
        'can_view_software_inventory': 'canViewSoftwareInventory'
    }

    def __init__(self, can_create_new_software_inventory=None, can_delete_software_inventory=None, can_view_software_inventory=None):  # noqa: E501
        """SoftwareInventoryRights - a model defined in Swagger"""  # noqa: E501

        self._can_create_new_software_inventory = None
        self._can_delete_software_inventory = None
        self._can_view_software_inventory = None
        self.discriminator = None

        if can_create_new_software_inventory is not None:
            self.can_create_new_software_inventory = can_create_new_software_inventory
        if can_delete_software_inventory is not None:
            self.can_delete_software_inventory = can_delete_software_inventory
        if can_view_software_inventory is not None:
            self.can_view_software_inventory = can_view_software_inventory

    @property
    def can_create_new_software_inventory(self):
        """Gets the can_create_new_software_inventory of this SoftwareInventoryRights.  # noqa: E501

        Right to create new software inventory.  # noqa: E501

        :return: The can_create_new_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_create_new_software_inventory

    @can_create_new_software_inventory.setter
    def can_create_new_software_inventory(self, can_create_new_software_inventory):
        """Sets the can_create_new_software_inventory of this SoftwareInventoryRights.

        Right to create new software inventory.  # noqa: E501

        :param can_create_new_software_inventory: The can_create_new_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :type: bool
        """

        self._can_create_new_software_inventory = can_create_new_software_inventory

    @property
    def can_delete_software_inventory(self):
        """Gets the can_delete_software_inventory of this SoftwareInventoryRights.  # noqa: E501

        Right to delete software inventory.  # noqa: E501

        :return: The can_delete_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_delete_software_inventory

    @can_delete_software_inventory.setter
    def can_delete_software_inventory(self, can_delete_software_inventory):
        """Sets the can_delete_software_inventory of this SoftwareInventoryRights.

        Right to delete software inventory.  # noqa: E501

        :param can_delete_software_inventory: The can_delete_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :type: bool
        """

        self._can_delete_software_inventory = can_delete_software_inventory

    @property
    def can_view_software_inventory(self):
        """Gets the can_view_software_inventory of this SoftwareInventoryRights.  # noqa: E501

        Right to view software inventory.  # noqa: E501

        :return: The can_view_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_software_inventory

    @can_view_software_inventory.setter
    def can_view_software_inventory(self, can_view_software_inventory):
        """Sets the can_view_software_inventory of this SoftwareInventoryRights.

        Right to view software inventory.  # noqa: E501

        :param can_view_software_inventory: The can_view_software_inventory of this SoftwareInventoryRights.  # noqa: E501
        :type: bool
        """

        self._can_view_software_inventory = can_view_software_inventory

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
        if issubclass(SoftwareInventoryRights, dict):
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
        if not isinstance(other, SoftwareInventoryRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

