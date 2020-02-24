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


class LicenseRateRights(object):
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
        'can_save_license_rates': 'bool',
        'can_view_license_rates': 'bool'
    }

    attribute_map = {
        'can_save_license_rates': 'canSaveLicenseRates',
        'can_view_license_rates': 'canViewLicenseRates'
    }

    def __init__(self, can_save_license_rates=None, can_view_license_rates=None):  # noqa: E501
        """LicenseRateRights - a model defined in Swagger"""  # noqa: E501

        self._can_save_license_rates = None
        self._can_view_license_rates = None
        self.discriminator = None

        if can_save_license_rates is not None:
            self.can_save_license_rates = can_save_license_rates
        if can_view_license_rates is not None:
            self.can_view_license_rates = can_view_license_rates

    @property
    def can_save_license_rates(self):
        """Gets the can_save_license_rates of this LicenseRateRights.  # noqa: E501

        Right to save license rates.  # noqa: E501

        :return: The can_save_license_rates of this LicenseRateRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_save_license_rates

    @can_save_license_rates.setter
    def can_save_license_rates(self, can_save_license_rates):
        """Sets the can_save_license_rates of this LicenseRateRights.

        Right to save license rates.  # noqa: E501

        :param can_save_license_rates: The can_save_license_rates of this LicenseRateRights.  # noqa: E501
        :type: bool
        """

        self._can_save_license_rates = can_save_license_rates

    @property
    def can_view_license_rates(self):
        """Gets the can_view_license_rates of this LicenseRateRights.  # noqa: E501

        Right to view license rates.  # noqa: E501

        :return: The can_view_license_rates of this LicenseRateRights.  # noqa: E501
        :rtype: bool
        """
        return self._can_view_license_rates

    @can_view_license_rates.setter
    def can_view_license_rates(self, can_view_license_rates):
        """Sets the can_view_license_rates of this LicenseRateRights.

        Right to view license rates.  # noqa: E501

        :param can_view_license_rates: The can_view_license_rates of this LicenseRateRights.  # noqa: E501
        :type: bool
        """

        self._can_view_license_rates = can_view_license_rates

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
        if issubclass(LicenseRateRights, dict):
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
        if not isinstance(other, LicenseRateRights):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

