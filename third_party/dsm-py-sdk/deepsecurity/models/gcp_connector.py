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


class GCPConnector(object):
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
        'name': 'str',
        'service_account': 'str',
        'owner_project_id': 'str',
        'private_key_id': 'str',
        'client_email': 'str',
        'id': 'int'
    }

    attribute_map = {
        'name': 'name',
        'service_account': 'serviceAccount',
        'owner_project_id': 'ownerProjectID',
        'private_key_id': 'privateKeyID',
        'client_email': 'clientEmail',
        'id': 'ID'
    }

    def __init__(self, name=None, service_account=None, owner_project_id=None, private_key_id=None, client_email=None, id=None):  # noqa: E501
        """GCPConnector - a model defined in Swagger"""  # noqa: E501

        self._name = None
        self._service_account = None
        self._owner_project_id = None
        self._private_key_id = None
        self._client_email = None
        self._id = None
        self.discriminator = None

        if name is not None:
            self.name = name
        if service_account is not None:
            self.service_account = service_account
        if owner_project_id is not None:
            self.owner_project_id = owner_project_id
        if private_key_id is not None:
            self.private_key_id = private_key_id
        if client_email is not None:
            self.client_email = client_email
        if id is not None:
            self.id = id

    @property
    def name(self):
        """Gets the name of this GCPConnector.  # noqa: E501

        Display name of the connector.  # noqa: E501

        :return: The name of this GCPConnector.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this GCPConnector.

        Display name of the connector.  # noqa: E501

        :param name: The name of this GCPConnector.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def service_account(self):
        """Gets the service_account of this GCPConnector.  # noqa: E501

        Service account of the connector, base64-encoded.  # noqa: E501

        :return: The service_account of this GCPConnector.  # noqa: E501
        :rtype: str
        """
        return self._service_account

    @service_account.setter
    def service_account(self, service_account):
        """Sets the service_account of this GCPConnector.

        Service account of the connector, base64-encoded.  # noqa: E501

        :param service_account: The service_account of this GCPConnector.  # noqa: E501
        :type: str
        """

        self._service_account = service_account

    @property
    def owner_project_id(self):
        """Gets the owner_project_id of this GCPConnector.  # noqa: E501

        The project ID which owns the service account.  # noqa: E501

        :return: The owner_project_id of this GCPConnector.  # noqa: E501
        :rtype: str
        """
        return self._owner_project_id

    @owner_project_id.setter
    def owner_project_id(self, owner_project_id):
        """Sets the owner_project_id of this GCPConnector.

        The project ID which owns the service account.  # noqa: E501

        :param owner_project_id: The owner_project_id of this GCPConnector.  # noqa: E501
        :type: str
        """

        self._owner_project_id = owner_project_id

    @property
    def private_key_id(self):
        """Gets the private_key_id of this GCPConnector.  # noqa: E501

        Private key ID of the GCP service account.  # noqa: E501

        :return: The private_key_id of this GCPConnector.  # noqa: E501
        :rtype: str
        """
        return self._private_key_id

    @private_key_id.setter
    def private_key_id(self, private_key_id):
        """Sets the private_key_id of this GCPConnector.

        Private key ID of the GCP service account.  # noqa: E501

        :param private_key_id: The private_key_id of this GCPConnector.  # noqa: E501
        :type: str
        """

        self._private_key_id = private_key_id

    @property
    def client_email(self):
        """Gets the client_email of this GCPConnector.  # noqa: E501

        Client email of the GCP service account.  # noqa: E501

        :return: The client_email of this GCPConnector.  # noqa: E501
        :rtype: str
        """
        return self._client_email

    @client_email.setter
    def client_email(self, client_email):
        """Sets the client_email of this GCPConnector.

        Client email of the GCP service account.  # noqa: E501

        :param client_email: The client_email of this GCPConnector.  # noqa: E501
        :type: str
        """

        self._client_email = client_email

    @property
    def id(self):
        """Gets the id of this GCPConnector.  # noqa: E501

        ID of the connector.  # noqa: E501

        :return: The id of this GCPConnector.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this GCPConnector.

        ID of the connector.  # noqa: E501

        :param id: The id of this GCPConnector.  # noqa: E501
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
        if issubclass(GCPConnector, dict):
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
        if not isinstance(other, GCPConnector):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

