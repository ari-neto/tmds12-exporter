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


class InventoryItem(object):
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
        'vendor_name': 'str',
        'product_name': 'str',
        'product_version': 'str',
        'file_version': 'str',
        'file_description': 'str',
        'category': 'str',
        'sha256': 'str',
        'sha1': 'str',
        'md5': 'str',
        'file_name': 'str',
        'path': 'str',
        'size': 'int',
        'id': 'int'
    }

    attribute_map = {
        'vendor_name': 'vendorName',
        'product_name': 'productName',
        'product_version': 'productVersion',
        'file_version': 'fileVersion',
        'file_description': 'fileDescription',
        'category': 'category',
        'sha256': 'sha256',
        'sha1': 'sha1',
        'md5': 'md5',
        'file_name': 'fileName',
        'path': 'path',
        'size': 'size',
        'id': 'ID'
    }

    def __init__(self, vendor_name=None, product_name=None, product_version=None, file_version=None, file_description=None, category=None, sha256=None, sha1=None, md5=None, file_name=None, path=None, size=None, id=None):  # noqa: E501
        """InventoryItem - a model defined in Swagger"""  # noqa: E501

        self._vendor_name = None
        self._product_name = None
        self._product_version = None
        self._file_version = None
        self._file_description = None
        self._category = None
        self._sha256 = None
        self._sha1 = None
        self._md5 = None
        self._file_name = None
        self._path = None
        self._size = None
        self._id = None
        self.discriminator = None

        if vendor_name is not None:
            self.vendor_name = vendor_name
        if product_name is not None:
            self.product_name = product_name
        if product_version is not None:
            self.product_version = product_version
        if file_version is not None:
            self.file_version = file_version
        if file_description is not None:
            self.file_description = file_description
        if category is not None:
            self.category = category
        if sha256 is not None:
            self.sha256 = sha256
        if sha1 is not None:
            self.sha1 = sha1
        if md5 is not None:
            self.md5 = md5
        if file_name is not None:
            self.file_name = file_name
        if path is not None:
            self.path = path
        if size is not None:
            self.size = size
        if id is not None:
            self.id = id

    @property
    def vendor_name(self):
        """Gets the vendor_name of this InventoryItem.  # noqa: E501

        Vendor name of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The vendor_name of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._vendor_name

    @vendor_name.setter
    def vendor_name(self, vendor_name):
        """Sets the vendor_name of this InventoryItem.

        Vendor name of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param vendor_name: The vendor_name of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._vendor_name = vendor_name

    @property
    def product_name(self):
        """Gets the product_name of this InventoryItem.  # noqa: E501

        Product name of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The product_name of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._product_name

    @product_name.setter
    def product_name(self, product_name):
        """Sets the product_name of this InventoryItem.

        Product name of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param product_name: The product_name of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._product_name = product_name

    @property
    def product_version(self):
        """Gets the product_version of this InventoryItem.  # noqa: E501

        Product version of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The product_version of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._product_version

    @product_version.setter
    def product_version(self, product_version):
        """Sets the product_version of this InventoryItem.

        Product version of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param product_version: The product_version of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._product_version = product_version

    @property
    def file_version(self):
        """Gets the file_version of this InventoryItem.  # noqa: E501

        File version of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The file_version of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._file_version

    @file_version.setter
    def file_version(self, file_version):
        """Sets the file_version of this InventoryItem.

        File version of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param file_version: The file_version of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._file_version = file_version

    @property
    def file_description(self):
        """Gets the file_description of this InventoryItem.  # noqa: E501

        File description of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The file_description of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._file_description

    @file_description.setter
    def file_description(self, file_description):
        """Sets the file_description of this InventoryItem.

        File description of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param file_description: The file_description of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._file_description = file_description

    @property
    def category(self):
        """Gets the category of this InventoryItem.  # noqa: E501

        File category of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :return: The category of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._category

    @category.setter
    def category(self, category):
        """Sets the category of this InventoryItem.

        File category of the inventory item as reported by the package management system on the computer. Searchable as String.  # noqa: E501

        :param category: The category of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._category = category

    @property
    def sha256(self):
        """Gets the sha256 of this InventoryItem.  # noqa: E501

        SHA-256 hash of the inventory item. Searchable as String.  # noqa: E501

        :return: The sha256 of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._sha256

    @sha256.setter
    def sha256(self, sha256):
        """Sets the sha256 of this InventoryItem.

        SHA-256 hash of the inventory item. Searchable as String.  # noqa: E501

        :param sha256: The sha256 of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._sha256 = sha256

    @property
    def sha1(self):
        """Gets the sha1 of this InventoryItem.  # noqa: E501

        SHA-1 hash of the inventory item. Searchable as String.  # noqa: E501

        :return: The sha1 of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._sha1

    @sha1.setter
    def sha1(self, sha1):
        """Sets the sha1 of this InventoryItem.

        SHA-1 hash of the inventory item. Searchable as String.  # noqa: E501

        :param sha1: The sha1 of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._sha1 = sha1

    @property
    def md5(self):
        """Gets the md5 of this InventoryItem.  # noqa: E501

        MD5 hash of the inventory item. Searchable as String.  # noqa: E501

        :return: The md5 of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._md5

    @md5.setter
    def md5(self, md5):
        """Sets the md5 of this InventoryItem.

        MD5 hash of the inventory item. Searchable as String.  # noqa: E501

        :param md5: The md5 of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._md5 = md5

    @property
    def file_name(self):
        """Gets the file_name of this InventoryItem.  # noqa: E501

        File name of the inventory item. Searchable as String.  # noqa: E501

        :return: The file_name of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._file_name

    @file_name.setter
    def file_name(self, file_name):
        """Sets the file_name of this InventoryItem.

        File name of the inventory item. Searchable as String.  # noqa: E501

        :param file_name: The file_name of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._file_name = file_name

    @property
    def path(self):
        """Gets the path of this InventoryItem.  # noqa: E501

        File path of the inventory item. Searchable as String.  # noqa: E501

        :return: The path of this InventoryItem.  # noqa: E501
        :rtype: str
        """
        return self._path

    @path.setter
    def path(self, path):
        """Sets the path of this InventoryItem.

        File path of the inventory item. Searchable as String.  # noqa: E501

        :param path: The path of this InventoryItem.  # noqa: E501
        :type: str
        """

        self._path = path

    @property
    def size(self):
        """Gets the size of this InventoryItem.  # noqa: E501

        File size of the inventory item in bytes. Searchable as Numeric.  # noqa: E501

        :return: The size of this InventoryItem.  # noqa: E501
        :rtype: int
        """
        return self._size

    @size.setter
    def size(self, size):
        """Sets the size of this InventoryItem.

        File size of the inventory item in bytes. Searchable as Numeric.  # noqa: E501

        :param size: The size of this InventoryItem.  # noqa: E501
        :type: int
        """

        self._size = size

    @property
    def id(self):
        """Gets the id of this InventoryItem.  # noqa: E501

        ID of the inventory item. Searchable as ID.  # noqa: E501

        :return: The id of this InventoryItem.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this InventoryItem.

        ID of the inventory item. Searchable as ID.  # noqa: E501

        :param id: The id of this InventoryItem.  # noqa: E501
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
        if issubclass(InventoryItem, dict):
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
        if not isinstance(other, InventoryItem):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

