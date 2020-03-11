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


class Administrator(object):
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
        'username': 'str',
        'password': 'str',
        'full_name': 'str',
        'description': 'str',
        'role_id': 'int',
        'locale': 'str',
        'time_zone': 'str',
        'time_format': 'str',
        'password_never_expires': 'bool',
        'active': 'bool',
        'mfa_type': 'str',
        'phone_number': 'str',
        'mobile_number': 'str',
        'pager_number': 'str',
        'email_address': 'str',
        'primary_contact': 'bool',
        'receive_notifications': 'bool',
        'report_pdf_password_enabled': 'bool',
        'report_pdf_password': 'str',
        'created': 'int',
        'last_password_change': 'int',
        'last_sign_in': 'int',
        'unlock_time': 'int',
        'unsuccessful_sign_in_attempts': 'int',
        'directory_name': 'str',
        'directory_info': 'str',
        'external': 'bool',
        'external_user_id': 'str',
        'type': 'str',
        'read_only': 'bool',
        'id': 'int',
        'utc_offset': 'str'
    }

    attribute_map = {
        'username': 'username',
        'password': 'password',
        'full_name': 'fullName',
        'description': 'description',
        'role_id': 'roleID',
        'locale': 'locale',
        'time_zone': 'timeZone',
        'time_format': 'timeFormat',
        'password_never_expires': 'passwordNeverExpires',
        'active': 'active',
        'mfa_type': 'mfaType',
        'phone_number': 'phoneNumber',
        'mobile_number': 'mobileNumber',
        'pager_number': 'pagerNumber',
        'email_address': 'emailAddress',
        'primary_contact': 'primaryContact',
        'receive_notifications': 'receiveNotifications',
        'report_pdf_password_enabled': 'reportPDFPasswordEnabled',
        'report_pdf_password': 'reportPDFPassword',
        'created': 'created',
        'last_password_change': 'lastPasswordChange',
        'last_sign_in': 'lastSignIn',
        'unlock_time': 'unlockTime',
        'unsuccessful_sign_in_attempts': 'unsuccessfulSignInAttempts',
        'directory_name': 'directoryName',
        'directory_info': 'directoryInfo',
        'external': 'external',
        'external_user_id': 'externalUserID',
        'type': 'type',
        'read_only': 'readOnly',
        'id': 'ID',
        'utc_offset': 'UTCOffset'
    }

    def __init__(self, username=None, password=None, full_name=None, description=None, role_id=None, locale=None, time_zone=None, time_format=None, password_never_expires=None, active=None, mfa_type=None, phone_number=None, mobile_number=None, pager_number=None, email_address=None, primary_contact=None, receive_notifications=None, report_pdf_password_enabled=None, report_pdf_password=None, created=None, last_password_change=None, last_sign_in=None, unlock_time=None, unsuccessful_sign_in_attempts=None, directory_name=None, directory_info=None, external=None, external_user_id=None, type=None, read_only=None, id=None, utc_offset=None):  # noqa: E501
        """Administrator - a model defined in Swagger"""  # noqa: E501

        self._username = None
        self._password = None
        self._full_name = None
        self._description = None
        self._role_id = None
        self._locale = None
        self._time_zone = None
        self._time_format = None
        self._password_never_expires = None
        self._active = None
        self._mfa_type = None
        self._phone_number = None
        self._mobile_number = None
        self._pager_number = None
        self._email_address = None
        self._primary_contact = None
        self._receive_notifications = None
        self._report_pdf_password_enabled = None
        self._report_pdf_password = None
        self._created = None
        self._last_password_change = None
        self._last_sign_in = None
        self._unlock_time = None
        self._unsuccessful_sign_in_attempts = None
        self._directory_name = None
        self._directory_info = None
        self._external = None
        self._external_user_id = None
        self._type = None
        self._read_only = None
        self._id = None
        self._utc_offset = None
        self.discriminator = None

        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if full_name is not None:
            self.full_name = full_name
        if description is not None:
            self.description = description
        if role_id is not None:
            self.role_id = role_id
        if locale is not None:
            self.locale = locale
        if time_zone is not None:
            self.time_zone = time_zone
        if time_format is not None:
            self.time_format = time_format
        if password_never_expires is not None:
            self.password_never_expires = password_never_expires
        if active is not None:
            self.active = active
        if mfa_type is not None:
            self.mfa_type = mfa_type
        if phone_number is not None:
            self.phone_number = phone_number
        if mobile_number is not None:
            self.mobile_number = mobile_number
        if pager_number is not None:
            self.pager_number = pager_number
        if email_address is not None:
            self.email_address = email_address
        if primary_contact is not None:
            self.primary_contact = primary_contact
        if receive_notifications is not None:
            self.receive_notifications = receive_notifications
        if report_pdf_password_enabled is not None:
            self.report_pdf_password_enabled = report_pdf_password_enabled
        if report_pdf_password is not None:
            self.report_pdf_password = report_pdf_password
        if created is not None:
            self.created = created
        if last_password_change is not None:
            self.last_password_change = last_password_change
        if last_sign_in is not None:
            self.last_sign_in = last_sign_in
        if unlock_time is not None:
            self.unlock_time = unlock_time
        if unsuccessful_sign_in_attempts is not None:
            self.unsuccessful_sign_in_attempts = unsuccessful_sign_in_attempts
        if directory_name is not None:
            self.directory_name = directory_name
        if directory_info is not None:
            self.directory_info = directory_info
        if external is not None:
            self.external = external
        if external_user_id is not None:
            self.external_user_id = external_user_id
        if type is not None:
            self.type = type
        if read_only is not None:
            self.read_only = read_only
        if id is not None:
            self.id = id
        if utc_offset is not None:
            self.utc_offset = utc_offset

    @property
    def username(self):
        """Gets the username of this Administrator.  # noqa: E501

        Username of the Administrator. Searchable as String.  # noqa: E501

        :return: The username of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._username

    @username.setter
    def username(self, username):
        """Sets the username of this Administrator.

        Username of the Administrator. Searchable as String.  # noqa: E501

        :param username: The username of this Administrator.  # noqa: E501
        :type: str
        """

        self._username = username

    @property
    def password(self):
        """Gets the password of this Administrator.  # noqa: E501

        Password of the Administrator.  # noqa: E501

        :return: The password of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._password

    @password.setter
    def password(self, password):
        """Sets the password of this Administrator.

        Password of the Administrator.  # noqa: E501

        :param password: The password of this Administrator.  # noqa: E501
        :type: str
        """

        self._password = password

    @property
    def full_name(self):
        """Gets the full_name of this Administrator.  # noqa: E501

        Full name of the Administrator. Searchable as String.  # noqa: E501

        :return: The full_name of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._full_name

    @full_name.setter
    def full_name(self, full_name):
        """Sets the full_name of this Administrator.

        Full name of the Administrator. Searchable as String.  # noqa: E501

        :param full_name: The full_name of this Administrator.  # noqa: E501
        :type: str
        """

        self._full_name = full_name

    @property
    def description(self):
        """Gets the description of this Administrator.  # noqa: E501

        Description of the Administrator. Searchable as String.  # noqa: E501

        :return: The description of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._description

    @description.setter
    def description(self, description):
        """Sets the description of this Administrator.

        Description of the Administrator. Searchable as String.  # noqa: E501

        :param description: The description of this Administrator.  # noqa: E501
        :type: str
        """

        self._description = description

    @property
    def role_id(self):
        """Gets the role_id of this Administrator.  # noqa: E501

        ID of the role assigned to the Administrator. Searchable as Numeric.  # noqa: E501

        :return: The role_id of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._role_id

    @role_id.setter
    def role_id(self, role_id):
        """Sets the role_id of this Administrator.

        ID of the role assigned to the Administrator. Searchable as Numeric.  # noqa: E501

        :param role_id: The role_id of this Administrator.  # noqa: E501
        :type: int
        """

        self._role_id = role_id

    @property
    def locale(self):
        """Gets the locale of this Administrator.  # noqa: E501

        Locale of the Administrator.  # noqa: E501

        :return: The locale of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._locale

    @locale.setter
    def locale(self, locale):
        """Sets the locale of this Administrator.

        Locale of the Administrator.  # noqa: E501

        :param locale: The locale of this Administrator.  # noqa: E501
        :type: str
        """
        allowed_values = ["en-US", "ja-JP"]  # noqa: E501
        if locale not in allowed_values:
            raise ValueError(
                "Invalid value for `locale` ({0}), must be one of {1}"  # noqa: E501
                .format(locale, allowed_values)
            )

        self._locale = locale

    @property
    def time_zone(self):
        """Gets the time_zone of this Administrator.  # noqa: E501

        Time zone of the Administrator. Searchable as String.  # noqa: E501

        :return: The time_zone of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._time_zone

    @time_zone.setter
    def time_zone(self, time_zone):
        """Sets the time_zone of this Administrator.

        Time zone of the Administrator. Searchable as String.  # noqa: E501

        :param time_zone: The time_zone of this Administrator.  # noqa: E501
        :type: str
        """

        self._time_zone = time_zone

    @property
    def time_format(self):
        """Gets the time_format of this Administrator.  # noqa: E501

        Time format preference of the Administrator. Can be either the 12-hour format or the 24-hour format. Searchable as Choice.  # noqa: E501

        :return: The time_format of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._time_format

    @time_format.setter
    def time_format(self, time_format):
        """Sets the time_format of this Administrator.

        Time format preference of the Administrator. Can be either the 12-hour format or the 24-hour format. Searchable as Choice.  # noqa: E501

        :param time_format: The time_format of this Administrator.  # noqa: E501
        :type: str
        """
        allowed_values = ["12", "24"]  # noqa: E501
        if time_format not in allowed_values:
            raise ValueError(
                "Invalid value for `time_format` ({0}), must be one of {1}"  # noqa: E501
                .format(time_format, allowed_values)
            )

        self._time_format = time_format

    @property
    def password_never_expires(self):
        """Gets the password_never_expires of this Administrator.  # noqa: E501

        Enabled if the Administrator's password never expires. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :return: The password_never_expires of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._password_never_expires

    @password_never_expires.setter
    def password_never_expires(self, password_never_expires):
        """Sets the password_never_expires of this Administrator.

        Enabled if the Administrator's password never expires. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :param password_never_expires: The password_never_expires of this Administrator.  # noqa: E501
        :type: bool
        """

        self._password_never_expires = password_never_expires

    @property
    def active(self):
        """Gets the active of this Administrator.  # noqa: E501

        If set to `true`, the Administrator can authenticate. If set to `false`, the Administrator is locked out. Searchable as Boolean.  # noqa: E501

        :return: The active of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._active

    @active.setter
    def active(self, active):
        """Sets the active of this Administrator.

        If set to `true`, the Administrator can authenticate. If set to `false`, the Administrator is locked out. Searchable as Boolean.  # noqa: E501

        :param active: The active of this Administrator.  # noqa: E501
        :type: bool
        """

        self._active = active

    @property
    def mfa_type(self):
        """Gets the mfa_type of this Administrator.  # noqa: E501

        Specifies the type of multi-factor authentication used to authenticate the Administrator. Defaults to `none`. Searchable as Choice.  # noqa: E501

        :return: The mfa_type of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._mfa_type

    @mfa_type.setter
    def mfa_type(self, mfa_type):
        """Sets the mfa_type of this Administrator.

        Specifies the type of multi-factor authentication used to authenticate the Administrator. Defaults to `none`. Searchable as Choice.  # noqa: E501

        :param mfa_type: The mfa_type of this Administrator.  # noqa: E501
        :type: str
        """
        allowed_values = ["none", "local-totp"]  # noqa: E501
        if mfa_type not in allowed_values:
            raise ValueError(
                "Invalid value for `mfa_type` ({0}), must be one of {1}"  # noqa: E501
                .format(mfa_type, allowed_values)
            )

        self._mfa_type = mfa_type

    @property
    def phone_number(self):
        """Gets the phone_number of this Administrator.  # noqa: E501

        Phone number of the Administrator. Searchable as String.  # noqa: E501

        :return: The phone_number of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._phone_number

    @phone_number.setter
    def phone_number(self, phone_number):
        """Sets the phone_number of this Administrator.

        Phone number of the Administrator. Searchable as String.  # noqa: E501

        :param phone_number: The phone_number of this Administrator.  # noqa: E501
        :type: str
        """

        self._phone_number = phone_number

    @property
    def mobile_number(self):
        """Gets the mobile_number of this Administrator.  # noqa: E501

        Mobile number of the Administrator. Searchable as String.  # noqa: E501

        :return: The mobile_number of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._mobile_number

    @mobile_number.setter
    def mobile_number(self, mobile_number):
        """Sets the mobile_number of this Administrator.

        Mobile number of the Administrator. Searchable as String.  # noqa: E501

        :param mobile_number: The mobile_number of this Administrator.  # noqa: E501
        :type: str
        """

        self._mobile_number = mobile_number

    @property
    def pager_number(self):
        """Gets the pager_number of this Administrator.  # noqa: E501

        Pager number of the Administrator. Searchable as String.  # noqa: E501

        :return: The pager_number of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._pager_number

    @pager_number.setter
    def pager_number(self, pager_number):
        """Sets the pager_number of this Administrator.

        Pager number of the Administrator. Searchable as String.  # noqa: E501

        :param pager_number: The pager_number of this Administrator.  # noqa: E501
        :type: str
        """

        self._pager_number = pager_number

    @property
    def email_address(self):
        """Gets the email_address of this Administrator.  # noqa: E501

        Email address of the Administrator. Searchable as String.  # noqa: E501

        :return: The email_address of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._email_address

    @email_address.setter
    def email_address(self, email_address):
        """Sets the email_address of this Administrator.

        Email address of the Administrator. Searchable as String.  # noqa: E501

        :param email_address: The email_address of this Administrator.  # noqa: E501
        :type: str
        """

        self._email_address = email_address

    @property
    def primary_contact(self):
        """Gets the primary_contact of this Administrator.  # noqa: E501

        If set to `true`, the administrator is a primary contact. Primary contacts receive Deep Security as a Service account-related emails for that tenant. A valid `emailAddress` is required. Searchable as Boolean.  # noqa: E501

        :return: The primary_contact of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._primary_contact

    @primary_contact.setter
    def primary_contact(self, primary_contact):
        """Sets the primary_contact of this Administrator.

        If set to `true`, the administrator is a primary contact. Primary contacts receive Deep Security as a Service account-related emails for that tenant. A valid `emailAddress` is required. Searchable as Boolean.  # noqa: E501

        :param primary_contact: The primary_contact of this Administrator.  # noqa: E501
        :type: bool
        """

        self._primary_contact = primary_contact

    @property
    def receive_notifications(self):
        """Gets the receive_notifications of this Administrator.  # noqa: E501

        If set to `true`, alert emails will be sent to the Administrator. A valid `emailAddress` is required. Searchable as Boolean.  # noqa: E501

        :return: The receive_notifications of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._receive_notifications

    @receive_notifications.setter
    def receive_notifications(self, receive_notifications):
        """Sets the receive_notifications of this Administrator.

        If set to `true`, alert emails will be sent to the Administrator. A valid `emailAddress` is required. Searchable as Boolean.  # noqa: E501

        :param receive_notifications: The receive_notifications of this Administrator.  # noqa: E501
        :type: bool
        """

        self._receive_notifications = receive_notifications

    @property
    def report_pdf_password_enabled(self):
        """Gets the report_pdf_password_enabled of this Administrator.  # noqa: E501

        Controls whether the reports that the Administrator generates are password-protected. Set to `true` to password-protect, and `false` otherwise. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :return: The report_pdf_password_enabled of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._report_pdf_password_enabled

    @report_pdf_password_enabled.setter
    def report_pdf_password_enabled(self, report_pdf_password_enabled):
        """Sets the report_pdf_password_enabled of this Administrator.

        Controls whether the reports that the Administrator generates are password-protected. Set to `true` to password-protect, and `false` otherwise. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :param report_pdf_password_enabled: The report_pdf_password_enabled of this Administrator.  # noqa: E501
        :type: bool
        """

        self._report_pdf_password_enabled = report_pdf_password_enabled

    @property
    def report_pdf_password(self):
        """Gets the report_pdf_password of this Administrator.  # noqa: E501

        Password that protects the reports that the Administrator generates. Ignored when `reportPDFPasswordEnabled` is `false`.  # noqa: E501

        :return: The report_pdf_password of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._report_pdf_password

    @report_pdf_password.setter
    def report_pdf_password(self, report_pdf_password):
        """Sets the report_pdf_password of this Administrator.

        Password that protects the reports that the Administrator generates. Ignored when `reportPDFPasswordEnabled` is `false`.  # noqa: E501

        :param report_pdf_password: The report_pdf_password of this Administrator.  # noqa: E501
        :type: str
        """

        self._report_pdf_password = report_pdf_password

    @property
    def created(self):
        """Gets the created of this Administrator.  # noqa: E501

        Timestamp when the Administrator was created, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The created of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._created

    @created.setter
    def created(self, created):
        """Sets the created of this Administrator.

        Timestamp when the Administrator was created, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param created: The created of this Administrator.  # noqa: E501
        :type: int
        """

        self._created = created

    @property
    def last_password_change(self):
        """Gets the last_password_change of this Administrator.  # noqa: E501

        Timestamp when the Administrator's password was last changed, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The last_password_change of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._last_password_change

    @last_password_change.setter
    def last_password_change(self, last_password_change):
        """Sets the last_password_change of this Administrator.

        Timestamp when the Administrator's password was last changed, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param last_password_change: The last_password_change of this Administrator.  # noqa: E501
        :type: int
        """

        self._last_password_change = last_password_change

    @property
    def last_sign_in(self):
        """Gets the last_sign_in of this Administrator.  # noqa: E501

        Timestamp when the Administrator last signed in, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :return: The last_sign_in of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._last_sign_in

    @last_sign_in.setter
    def last_sign_in(self, last_sign_in):
        """Sets the last_sign_in of this Administrator.

        Timestamp when the Administrator last signed in, in milliseconds since epoch. Searchable as Date.  # noqa: E501

        :param last_sign_in: The last_sign_in of this Administrator.  # noqa: E501
        :type: int
        """

        self._last_sign_in = last_sign_in

    @property
    def unlock_time(self):
        """Gets the unlock_time of this Administrator.  # noqa: E501

        Timestamp at which the Administrator will be unlocked, in milliseconds since epoch. Ignored if the Administrator is not locked out using a time-based lock out scheme. Searchable as Date.  # noqa: E501

        :return: The unlock_time of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._unlock_time

    @unlock_time.setter
    def unlock_time(self, unlock_time):
        """Sets the unlock_time of this Administrator.

        Timestamp at which the Administrator will be unlocked, in milliseconds since epoch. Ignored if the Administrator is not locked out using a time-based lock out scheme. Searchable as Date.  # noqa: E501

        :param unlock_time: The unlock_time of this Administrator.  # noqa: E501
        :type: int
        """

        self._unlock_time = unlock_time

    @property
    def unsuccessful_sign_in_attempts(self):
        """Gets the unsuccessful_sign_in_attempts of this Administrator.  # noqa: E501

        Number of unsuccessful sign-in attempts for the Administrator. This number is reset to `0` when a successful authentication occurs. Searchable as Numeric.  # noqa: E501

        :return: The unsuccessful_sign_in_attempts of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._unsuccessful_sign_in_attempts

    @unsuccessful_sign_in_attempts.setter
    def unsuccessful_sign_in_attempts(self, unsuccessful_sign_in_attempts):
        """Sets the unsuccessful_sign_in_attempts of this Administrator.

        Number of unsuccessful sign-in attempts for the Administrator. This number is reset to `0` when a successful authentication occurs. Searchable as Numeric.  # noqa: E501

        :param unsuccessful_sign_in_attempts: The unsuccessful_sign_in_attempts of this Administrator.  # noqa: E501
        :type: int
        """

        self._unsuccessful_sign_in_attempts = unsuccessful_sign_in_attempts

    @property
    def directory_name(self):
        """Gets the directory_name of this Administrator.  # noqa: E501

        Security Account Manager (SAM) account name for the Administrator. Ignored if the Administrator is not managed by an identity provider. Searchable as String.  # noqa: E501

        :return: The directory_name of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._directory_name

    @directory_name.setter
    def directory_name(self, directory_name):
        """Sets the directory_name of this Administrator.

        Security Account Manager (SAM) account name for the Administrator. Ignored if the Administrator is not managed by an identity provider. Searchable as String.  # noqa: E501

        :param directory_name: The directory_name of this Administrator.  # noqa: E501
        :type: str
        """

        self._directory_name = directory_name

    @property
    def directory_info(self):
        """Gets the directory_info of this Administrator.  # noqa: E501

        Unique ID used for single sign-on using a Security Account Manager (SAM) identity provider. Ignored if the Administrator is not managed by an identity provider.  # noqa: E501

        :return: The directory_info of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._directory_info

    @directory_info.setter
    def directory_info(self, directory_info):
        """Sets the directory_info of this Administrator.

        Unique ID used for single sign-on using a Security Account Manager (SAM) identity provider. Ignored if the Administrator is not managed by an identity provider.  # noqa: E501

        :param directory_info: The directory_info of this Administrator.  # noqa: E501
        :type: str
        """

        self._directory_info = directory_info

    @property
    def external(self):
        """Gets the external of this Administrator.  # noqa: E501

        If set to `true` the Administrator is externally authenticated using SAML. Defaults to `false`. Ignored if the Administrator is not externally authenticated. Searchable as Boolean.  # noqa: E501

        :return: The external of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._external

    @external.setter
    def external(self, external):
        """Sets the external of this Administrator.

        If set to `true` the Administrator is externally authenticated using SAML. Defaults to `false`. Ignored if the Administrator is not externally authenticated. Searchable as Boolean.  # noqa: E501

        :param external: The external of this Administrator.  # noqa: E501
        :type: bool
        """

        self._external = external

    @property
    def external_user_id(self):
        """Gets the external_user_id of this Administrator.  # noqa: E501

        SAML User ID of the Administrator. Used to support external authentication of the Administrator. Ignored if the Administrator is not externally authenticated. Searchable as String.  # noqa: E501

        :return: The external_user_id of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._external_user_id

    @external_user_id.setter
    def external_user_id(self, external_user_id):
        """Sets the external_user_id of this Administrator.

        SAML User ID of the Administrator. Used to support external authentication of the Administrator. Ignored if the Administrator is not externally authenticated. Searchable as String.  # noqa: E501

        :param external_user_id: The external_user_id of this Administrator.  # noqa: E501
        :type: str
        """

        self._external_user_id = external_user_id

    @property
    def type(self):
        """Gets the type of this Administrator.  # noqa: E501

        Administrator account type. Can either be `normal` or `temporary`. Defaults to `normal`. Searchable as Choice.  # noqa: E501

        :return: The type of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """Sets the type of this Administrator.

        Administrator account type. Can either be `normal` or `temporary`. Defaults to `normal`. Searchable as Choice.  # noqa: E501

        :param type: The type of this Administrator.  # noqa: E501
        :type: str
        """
        allowed_values = ["normal", "temporary"]  # noqa: E501
        if type not in allowed_values:
            raise ValueError(
                "Invalid value for `type` ({0}), must be one of {1}"  # noqa: E501
                .format(type, allowed_values)
            )

        self._type = type

    @property
    def read_only(self):
        """Gets the read_only of this Administrator.  # noqa: E501

        Set to `true` if the Administrator is read-only. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :return: The read_only of this Administrator.  # noqa: E501
        :rtype: bool
        """
        return self._read_only

    @read_only.setter
    def read_only(self, read_only):
        """Sets the read_only of this Administrator.

        Set to `true` if the Administrator is read-only. Defaults to `false`. Searchable as Boolean.  # noqa: E501

        :param read_only: The read_only of this Administrator.  # noqa: E501
        :type: bool
        """

        self._read_only = read_only

    @property
    def id(self):
        """Gets the id of this Administrator.  # noqa: E501

        ID of the Administrator. Searchable as ID.  # noqa: E501

        :return: The id of this Administrator.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this Administrator.

        ID of the Administrator. Searchable as ID.  # noqa: E501

        :param id: The id of this Administrator.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def utc_offset(self):
        """Gets the utc_offset of this Administrator.  # noqa: E501

        UTC offset of the Administrator.  # noqa: E501

        :return: The utc_offset of this Administrator.  # noqa: E501
        :rtype: str
        """
        return self._utc_offset

    @utc_offset.setter
    def utc_offset(self, utc_offset):
        """Sets the utc_offset of this Administrator.

        UTC offset of the Administrator.  # noqa: E501

        :param utc_offset: The utc_offset of this Administrator.  # noqa: E501
        :type: str
        """

        self._utc_offset = utc_offset

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
        if issubclass(Administrator, dict):
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
        if not isinstance(other, Administrator):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

