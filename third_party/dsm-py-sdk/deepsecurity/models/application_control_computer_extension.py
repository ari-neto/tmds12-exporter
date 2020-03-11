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

from deepsecurity.models.computer_module_status import ComputerModuleStatus  # noqa: F401,E501


class ApplicationControlComputerExtension(object):
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
        'state': 'str',
        'module_status': 'ComputerModuleStatus',
        'block_unrecognized': 'bool',
        'ruleset_id': 'int',
        'maintenance_mode_status': 'str',
        'maintenance_mode_duration': 'int',
        'maintenance_mode_start_time': 'int',
        'maintenance_mode_end_time': 'int'
    }

    attribute_map = {
        'state': 'state',
        'module_status': 'moduleStatus',
        'block_unrecognized': 'blockUnrecognized',
        'ruleset_id': 'rulesetID',
        'maintenance_mode_status': 'maintenanceModeStatus',
        'maintenance_mode_duration': 'maintenanceModeDuration',
        'maintenance_mode_start_time': 'maintenanceModeStartTime',
        'maintenance_mode_end_time': 'maintenanceModeEndTime'
    }

    def __init__(self, state=None, module_status=None, block_unrecognized=None, ruleset_id=None, maintenance_mode_status=None, maintenance_mode_duration=None, maintenance_mode_start_time=None, maintenance_mode_end_time=None):  # noqa: E501
        """ApplicationControlComputerExtension - a model defined in Swagger"""  # noqa: E501

        self._state = None
        self._module_status = None
        self._block_unrecognized = None
        self._ruleset_id = None
        self._maintenance_mode_status = None
        self._maintenance_mode_duration = None
        self._maintenance_mode_start_time = None
        self._maintenance_mode_end_time = None
        self.discriminator = None

        if state is not None:
            self.state = state
        if module_status is not None:
            self.module_status = module_status
        if block_unrecognized is not None:
            self.block_unrecognized = block_unrecognized
        if ruleset_id is not None:
            self.ruleset_id = ruleset_id
        if maintenance_mode_status is not None:
            self.maintenance_mode_status = maintenance_mode_status
        if maintenance_mode_duration is not None:
            self.maintenance_mode_duration = maintenance_mode_duration
        if maintenance_mode_start_time is not None:
            self.maintenance_mode_start_time = maintenance_mode_start_time
        if maintenance_mode_end_time is not None:
            self.maintenance_mode_end_time = maintenance_mode_end_time

    @property
    def state(self):
        """Gets the state of this ApplicationControlComputerExtension.  # noqa: E501

        Module state.  # noqa: E501

        :return: The state of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: str
        """
        return self._state

    @state.setter
    def state(self, state):
        """Sets the state of this ApplicationControlComputerExtension.

        Module state.  # noqa: E501

        :param state: The state of this ApplicationControlComputerExtension.  # noqa: E501
        :type: str
        """
        allowed_values = ["inherited", "on", "off"]  # noqa: E501
        if state not in allowed_values:
            raise ValueError(
                "Invalid value for `state` ({0}), must be one of {1}"  # noqa: E501
                .format(state, allowed_values)
            )

        self._state = state

    @property
    def module_status(self):
        """Gets the module_status of this ApplicationControlComputerExtension.  # noqa: E501


        :return: The module_status of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: ComputerModuleStatus
        """
        return self._module_status

    @module_status.setter
    def module_status(self, module_status):
        """Sets the module_status of this ApplicationControlComputerExtension.


        :param module_status: The module_status of this ApplicationControlComputerExtension.  # noqa: E501
        :type: ComputerModuleStatus
        """

        self._module_status = module_status

    @property
    def block_unrecognized(self):
        """Gets the block_unrecognized of this ApplicationControlComputerExtension.  # noqa: E501

        Controls whether to block unrecognized software until it is explicitly allowed. Set to true to block.  # noqa: E501

        :return: The block_unrecognized of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: bool
        """
        return self._block_unrecognized

    @block_unrecognized.setter
    def block_unrecognized(self, block_unrecognized):
        """Sets the block_unrecognized of this ApplicationControlComputerExtension.

        Controls whether to block unrecognized software until it is explicitly allowed. Set to true to block.  # noqa: E501

        :param block_unrecognized: The block_unrecognized of this ApplicationControlComputerExtension.  # noqa: E501
        :type: bool
        """

        self._block_unrecognized = block_unrecognized

    @property
    def ruleset_id(self):
        """Gets the ruleset_id of this ApplicationControlComputerExtension.  # noqa: E501

        ID of the shared whitelist ruleset.  # noqa: E501

        :return: The ruleset_id of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: int
        """
        return self._ruleset_id

    @ruleset_id.setter
    def ruleset_id(self, ruleset_id):
        """Sets the ruleset_id of this ApplicationControlComputerExtension.

        ID of the shared whitelist ruleset.  # noqa: E501

        :param ruleset_id: The ruleset_id of this ApplicationControlComputerExtension.  # noqa: E501
        :type: int
        """

        self._ruleset_id = ruleset_id

    @property
    def maintenance_mode_status(self):
        """Gets the maintenance_mode_status of this ApplicationControlComputerExtension.  # noqa: E501

        Maintenance mode status.  # noqa: E501

        :return: The maintenance_mode_status of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: str
        """
        return self._maintenance_mode_status

    @maintenance_mode_status.setter
    def maintenance_mode_status(self, maintenance_mode_status):
        """Sets the maintenance_mode_status of this ApplicationControlComputerExtension.

        Maintenance mode status.  # noqa: E501

        :param maintenance_mode_status: The maintenance_mode_status of this ApplicationControlComputerExtension.  # noqa: E501
        :type: str
        """
        allowed_values = ["off", "start-requested", "on", "stop-requested", "reset-duration-requested"]  # noqa: E501
        if maintenance_mode_status not in allowed_values:
            raise ValueError(
                "Invalid value for `maintenance_mode_status` ({0}), must be one of {1}"  # noqa: E501
                .format(maintenance_mode_status, allowed_values)
            )

        self._maintenance_mode_status = maintenance_mode_status

    @property
    def maintenance_mode_duration(self):
        """Gets the maintenance_mode_duration of this ApplicationControlComputerExtension.  # noqa: E501

        Duration of maintenance mode in minutes.  # noqa: E501

        :return: The maintenance_mode_duration of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: int
        """
        return self._maintenance_mode_duration

    @maintenance_mode_duration.setter
    def maintenance_mode_duration(self, maintenance_mode_duration):
        """Sets the maintenance_mode_duration of this ApplicationControlComputerExtension.

        Duration of maintenance mode in minutes.  # noqa: E501

        :param maintenance_mode_duration: The maintenance_mode_duration of this ApplicationControlComputerExtension.  # noqa: E501
        :type: int
        """

        self._maintenance_mode_duration = maintenance_mode_duration

    @property
    def maintenance_mode_start_time(self):
        """Gets the maintenance_mode_start_time of this ApplicationControlComputerExtension.  # noqa: E501

        Timestamp of the date the maintenanceMode was started, in milliseconds since epoch.  # noqa: E501

        :return: The maintenance_mode_start_time of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: int
        """
        return self._maintenance_mode_start_time

    @maintenance_mode_start_time.setter
    def maintenance_mode_start_time(self, maintenance_mode_start_time):
        """Sets the maintenance_mode_start_time of this ApplicationControlComputerExtension.

        Timestamp of the date the maintenanceMode was started, in milliseconds since epoch.  # noqa: E501

        :param maintenance_mode_start_time: The maintenance_mode_start_time of this ApplicationControlComputerExtension.  # noqa: E501
        :type: int
        """

        self._maintenance_mode_start_time = maintenance_mode_start_time

    @property
    def maintenance_mode_end_time(self):
        """Gets the maintenance_mode_end_time of this ApplicationControlComputerExtension.  # noqa: E501

        Timestamp of the date the maintenanceMode was ended, in milliseconds since epoch.  # noqa: E501

        :return: The maintenance_mode_end_time of this ApplicationControlComputerExtension.  # noqa: E501
        :rtype: int
        """
        return self._maintenance_mode_end_time

    @maintenance_mode_end_time.setter
    def maintenance_mode_end_time(self, maintenance_mode_end_time):
        """Sets the maintenance_mode_end_time of this ApplicationControlComputerExtension.

        Timestamp of the date the maintenanceMode was ended, in milliseconds since epoch.  # noqa: E501

        :param maintenance_mode_end_time: The maintenance_mode_end_time of this ApplicationControlComputerExtension.  # noqa: E501
        :type: int
        """

        self._maintenance_mode_end_time = maintenance_mode_end_time

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
        if issubclass(ApplicationControlComputerExtension, dict):
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
        if not isinstance(other, ApplicationControlComputerExtension):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

