# Copyright (c) 2025, Palo Alto Networks
#
# Licensed under the Polyform Internal Use License 1.0.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
#
# https://polyformproject.org/licenses/internal-use/1.0.0
# (or)
# https://github.com/polyformproject/polyform-licenses/blob/76a278c4/PolyForm-Internal-Use-1.0.0.md
#
# As far as the law allows, the software comes as is, without any warranty
# or condition, and the licensor will not be liable to you for any damages
# arising out of these terms or the use or nature of the software, under
# any kind of legal claim.

import os
import warnings

from aisecurity.constants.base import (
    AI_SEC_API_ENDPOINT,
    AI_SEC_API_KEY,
    AI_SEC_API_TOKEN,
    DEFAULT_ENDPOINT,
    MAX_API_KEY_LENGTH,
    MAX_NUMBER_OF_RETRIES,
    MAX_TOKEN_LENGTH,
)
from aisecurity.exceptions import AISecSDKException, ErrorType
from aisecurity.logger import BaseLogger

if not (isinstance(DEFAULT_ENDPOINT, str) and DEFAULT_ENDPOINT.startswith("https://")):
    raise AISecSDKException(
        f"aisecurity.constants.base.DEFAULT_ENDPOINT must be an https:// URL (got: {DEFAULT_ENDPOINT!r})",
        ErrorType.AISEC_SDK_ERROR,
    )


class _Configuration(BaseLogger):
    def __init__(self):
        super().__init__()
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._api_token = None
        self._num_retries = MAX_NUMBER_OF_RETRIES

    def init(
        self,
        *,
        api_key: str | None = None,
        api_token: str | None = None,
        api_endpoint: str | None = None,
        num_retries: int | None = None,
    ):
        if api_endpoint:
            self.api_endpoint = api_endpoint
        elif api_endpoint := os.getenv(AI_SEC_API_ENDPOINT):
            self.api_endpoint = api_endpoint

        if api_key:
            self.api_key = api_key
        elif api_key := os.getenv(AI_SEC_API_KEY):
            self.api_key = api_key

        if api_token:
            self.api_token = api_token
        elif api_token := os.getenv(AI_SEC_API_TOKEN):
            self.api_token = api_token

        if not (self.api_key or self.api_token):
            self._log_and_raise(
                "Either api_key or api_token must be provided ",
                ErrorType.MISSING_VARIABLE,
            )

        if num_retries is not None:
            self.num_retries = num_retries

    def _log_and_raise(self, message, error_type):
        self.logger.error(f"event={self.init.__name__} {message}")
        raise AISecSDKException(message, error_type)

    @property
    def api_endpoint(self):
        return self._api_endpoint

    @api_endpoint.setter
    def api_endpoint(self, value):
        if value is None:
            value = DEFAULT_ENDPOINT
        if not isinstance(value, str):
            self._log_and_raise(
                "api_endpoint must be a string starting with https://",
                ErrorType.AISEC_SDK_ERROR,
            )
        normalised = value.strip()
        if not normalised.lower().startswith("https://"):
            scheme = normalised.split("://", 1)[0] if "://" in normalised else "<none>"
            self._log_and_raise(
                f"api_endpoint must use the https:// scheme to protect credentials in transit (got scheme={scheme!r})",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._api_endpoint = normalised
        self.logger.info(f"event={self.init.__name__} api_endpoint={self._api_endpoint} action=set")

    @property
    def api_key(self):
        return self._api_key

    @api_key.setter
    def api_key(self, value):
        if value is None or len(value) == 0:
            self._log_and_raise(
                "api_key can't be None",
                ErrorType.MISSING_VARIABLE,
            )
        if len(value) > MAX_API_KEY_LENGTH:
            self._log_and_raise(
                f"api_key can't exceed {MAX_API_KEY_LENGTH} bytes",
                ErrorType.AISEC_SDK_ERROR,
            )

        if self.api_token:
            warnings.warn("Both API key and OAuth token are configured. Consider using only one authentication method.")

        self._api_key = value
        self.logger.info(f"event={self.init.__name__} api_key value configured action=set")
        self.logger.debug(f"event={self.init.__name__} api_key_last8=*********{self._api_key[-8:]} action=set")

    @property
    def num_retries(self):
        return self._num_retries

    @num_retries.setter
    def num_retries(self, value):
        if not isinstance(value, int):
            raise AISecSDKException(
                f"Invalid num_retries value: {value}. num_retries must be an integer.",
                ErrorType.AISEC_SDK_ERROR,
            )
        if value < 0:
            raise AISecSDKException(
                f"Invalid num_retries value: {value}. num_retries must be a non-negative integer.",
                ErrorType.AISEC_SDK_ERROR,
            )
        self._num_retries = value
        self.logger.info(f"event={self.init.__name__} var={self._num_retries} action=set")

    @property
    def api_token(self):
        return self._api_token

    @api_token.setter
    def api_token(self, value):
        if value is None or len(value) == 0:
            self._log_and_raise(
                "api_token can't be None",
                ErrorType.MISSING_VARIABLE,
            )
        if len(value) > MAX_TOKEN_LENGTH:
            self._log_and_raise(
                f"api_token can't exceed {MAX_TOKEN_LENGTH} bytes",
                ErrorType.AISEC_SDK_ERROR,
            )
        if self.api_key:
            warnings.warn("Both API key and OAuth token are configured. Consider using only one authentication method.")

        self._api_token = value
        self.logger.info(f"event={self.init.__name__} api_token value configured action=set")
        self.logger.debug(f"event={self.init.__name__} api_token_last8=*********{self._api_token[-8:]} action=set")

    def reset(self):
        self._api_endpoint = DEFAULT_ENDPOINT
        self._api_key = None
        self._api_token = None
        self._num_retries = MAX_NUMBER_OF_RETRIES
        self.logger.info(f"event={self.reset.__name__} action=configuration_reset")


# TODO: Move away global/singleton configuration
global_configuration = _Configuration()
