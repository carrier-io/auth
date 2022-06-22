#!/usr/bin/python3
# coding=utf-8

#   Copyright 2022 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" Module """

import time
import functools

import flask  # pylint: disable=E0401
import cachetools  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401
from pylon.core.tools import module  # pylint: disable=E0401
from pylon.core.tools.context import Context as Holder  # pylint: disable=E0401


class Module(module.ModuleModel):  # pylint: disable=R0902
    """ Pylon module """

    def __init__(self, context, descriptor):
        self.context = context
        self.descriptor = descriptor
        # Decorators
        self.decorators = Holder()
        # RPC proxies
        self._rpcs = [
            [
                "get_referenced_auth_context",
                "auth_get_referenced_auth_context"
            ],
            ["get_session_cookie_name", "auth_get_session_cookie_name"],
            #
            ["register_auth_provider", "auth_register_auth_provider"],
            ["unregister_auth_provider", "auth_unregister_auth_provider"],
            #
            ["register_auth_processor", "auth_register_auth_processor"],
            ["unregister_auth_processor", "auth_unregister_auth_processor"],
            #
            [
                "register_credential_handler",
                "auth_register_credential_handler"
            ],
            [
                "unregister_credential_handler",
                "auth_unregister_credential_handler"
            ],
            #
            ["register_success_mapper", "auth_register_success_mapper"],
            ["unregister_success_mapper", "auth_unregister_success_mapper"],
            #
            ["register_info_mapper", "auth_register_info_mapper"],
            ["unregister_info_mapper", "auth_unregister_info_mapper"],
            #
            ["add_public_rule", "auth_add_public_rule"],
            ["remove_public_rule", "auth_remove_public_rule"],
            #
            ["add_user", "auth_add_user"],
            ["delete_user", "auth_delete_user"],
            ["get_user", "auth_get_user"],
            ["list_users", "auth_list_users"],
            #
            ["add_user_provider", "auth_add_user_provider"],
            ["remove_user_provider", "auth_remove_user_provider"],
            ["get_user_from_provider", "auth_get_user_from_provider"],
            ["list_user_providers", "auth_list_user_providers"],
            #
            ["add_group", "auth_add_group"],
            ["delete_group", "auth_delete_group"],
            ["get_group", "auth_get_group"],
            ["list_groups", "auth_list_groups"],
            ["walk_group_tree", "auth_walk_group_tree"],
            #
            ["add_group_provider", "auth_add_group_provider"],
            ["remove_group_provider", "auth_remove_group_provider"],
            ["get_group_from_provider", "auth_get_group_from_provider"],
            ["list_group_providers", "auth_list_group_providers"],
            #
            ["add_user_group", "auth_add_user_group"],
            ["remove_user_group", "auth_remove_user_group"],
            ["get_user_group_ids", "auth_get_user_group_ids"],
            ["get_user_groups", "auth_get_user_groups"],
            ["list_user_groups", "auth_list_user_groups"],
            #
            ["add_scope", "auth_add_scope"],
            ["delete_scope", "auth_delete_scope"],
            ["get_scope", "auth_get_scope"],
            ["list_scopes", "auth_list_scopes"],
            ["walk_scope_tree", "auth_walk_scope_tree"],
            #
            ["add_group_permission", "auth_add_group_permission"],
            ["remove_group_permission", "auth_remove_group_permission"],
            ["get_group_permissions", "auth_get_group_permissions"],
            ["list_group_permissions", "auth_list_group_permissions"],
            #
            ["add_user_permission", "auth_add_user_permission"],
            ["remove_user_permission", "auth_remove_user_permission"],
            ["get_user_permissions", "auth_get_user_permissions"],
            ["list_user_permissions", "auth_list_user_permissions"],
            #
            ["add_token", "auth_add_token"],
            ["delete_token", "auth_delete_token"],
            ["get_token", "auth_get_token"],
            ["list_tokens", "auth_list_tokens"],
            ["encode_token", "auth_encode_token"],
            ["decode_token", "auth_decode_token"],
            #
            ["add_token_permission", "auth_add_token_permission"],
            ["remove_token_permission", "auth_remove_token_permission"],
            ["get_token_permissions", "auth_get_token_permissions"],
            ["list_token_permissions", "auth_list_token_permissions"],
            ["resolve_token_permissions", "auth_resolve_token_permissions"],
        ]
        # SIO auth data
        self.sio_users = dict()  # sid -> auth_data

    #
    # Module
    #

    def init(self):
        """ Init module """
        log.info("Initializing module")
        # Add decorators
        self.decorators.check = self._decorator_check
        self.decorators.check_api = self._decorator_check_api
        self.decorators.check_slot = self._decorator_check_slot
        #
        self.decorators.sio_connect = self._decorator_sio_connect
        self.decorators.sio_disconnect = self._decorator_sio_disconnect
        self.decorators.sio_check = self._decorator_sio_check
        # Register RPC proxies
        for proxy_name, rpc_name in self._rpcs:
            if hasattr(self, proxy_name):
                raise RuntimeError(f"Name '{proxy_name}' is already set")
            #
            setattr(
                self, proxy_name,
                functools.partial(self.mocked_call, rpc_name)
            )
        # Register auth tool
        self.descriptor.register_tool("auth", self)
        # Add hooks
        self.context.app.before_request(self._before_request_hook)
        # Enable cache
        self.get_user_permissions = cachetools.cached(  # pylint: disable=W0201
            cache=cachetools.TTLCache(maxsize=1024, ttl=60)
        )(self.get_user_permissions)
        self.get_token_permissions = cachetools.cached(  # pylint: disable=W0201
            cache=cachetools.TTLCache(maxsize=1024, ttl=60)
        )(self.get_token_permissions)
        self.get_user = cachetools.cached(  # pylint: disable=W0201
            cache=cachetools.TTLCache(maxsize=1024, ttl=60)
        )(self.get_user)
        self.get_token = cachetools.cached(  # pylint: disable=W0201
            cache=cachetools.TTLCache(maxsize=1024, ttl=60)
        )(self.get_token)

    def mocked_call(self, rpc_name: str, *args, **kwargs):
        log.info('rpc_name: [%s] | args: %s | kwargs: %s', rpc_name, args, kwargs)
        from queue import Empty
        try:
            return self.context.rpc_manager.call_function_with_timeout(
                    rpc_name,
                    1,
                    *args,
                    **kwargs,
                )
        except Empty:
            log.warning('Call mocker RPC [%s]', rpc_name)


    def deinit(self):  # pylint: disable=R0201
        """ De-init module """
        log.info("De-initializing module")
        # Unregister auth tool
        self.descriptor.unregister_tool("auth")
        # Unregister RPC proxies
        for proxy_name, _ in self._rpcs:
            delattr(self, proxy_name)

    #
    # Ping: check if auth pylon is connected
    #

    def ping(self, retry_interval=5, rpc_timeout=1, max_retries=None):
        """ Check if auth pylon is connected """
        return True
        retries_done = 0
        #
        while True:
            try:
                self.context.rpc_manager.timeout(rpc_timeout).auth_ping()
                return True
            except:  # pylint: disable=W0702
                retries_done += 1
                #
                if max_retries is not None and retries_done >= max_retries:
                    return False
                #
                time.sleep(retry_interval)

    #
    # Hooks
    #

    def _before_request_hook(self):  # pylint: disable=R0201
        flask.g.auth = Holder()
        #
        flask.g.auth.type = flask.request.headers.get("X-Auth-Type", "public")
        flask.g.auth.id = flask.request.headers.get("X-Auth-ID", "-")
        flask.g.auth.reference = flask.request.headers.get(
            "X-Auth-Reference", "-"
        )
        #
        try:
            flask.g.auth.id = int(flask.g.auth.id)
        except:
            flask.g.auth.id = "-"

    #
    # Decorators
    #

    #
    # Decorators: SIO
    #

    def _decorator_sio_connect(self):
        """ SIO: on connect save auth data for SID """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                environ = _args[2]
                #
                self.sio_users[sid] = self.sio_make_auth_data(environ)
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    def _decorator_sio_disconnect(self):
        """ SIO: on disconnect remove auth data for SID """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                #
                self.sio_users.pop(sid, None)
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    def _decorator_sio_check(self, permissions, scope_id=1):
        """ SIO: on event """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                sid = _args[1]
                #
                current_permissions = self.resolve_permissions(
                    scope_id, auth_data=self.sio_users[sid]
                )
                #
                if "global_admin" not in current_permissions and \
                        not set(permissions).issubset(set(current_permissions)):
                    return None
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    #
    # Decorators
    #

    def _decorator_check(self, permissions, scope_id=1):
        """ Check access to route """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                #
                current_permissions = self.resolve_permissions(scope_id)
                #
                if "global_admin" not in current_permissions and \
                        not set(permissions).issubset(set(current_permissions)):
                    return self.access_denied_reply()
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    def _decorator_check_api(
        self, permissions, scope_id=1,
        access_denied_reply={"ok": False, "error": "access_denied"},
    ):
        """ Check access to API """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                #
                current_permissions = self.resolve_permissions(scope_id)
                #
                if "global_admin" not in current_permissions and \
                        not set(permissions).issubset(set(current_permissions)):
                    return access_denied_reply
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    def _decorator_check_slot(
            self, permissions, scope_id=1, access_denied_reply=None,
    ):
        """ Check access to slot """
        #
        def _decorator(func):
            #
            @functools.wraps(func)
            def _decorated(*_args, **_kvargs):
                state = _args[-1]
                #
                current_permissions = self.resolve_permissions(
                    scope_id, auth_data=state.auth
                )
                #
                if "global_admin" not in current_permissions and \
                        not set(permissions).issubset(set(current_permissions)):
                    return access_denied_reply
                #
                return func(*_args, **_kvargs)
            #
            return _decorated
        #
        return _decorator

    #
    # Tools
    #

    #
    # Tools: access denied
    #

    def access_denied_reply(self):
        """ Traefik/client: bad auth reply/redirect """
        if "auth_denied_url" in self.descriptor.config:
            return flask.redirect(self.descriptor.config.get("auth_denied_url"))
        return flask.make_response("Access Denied", 403)

    #
    # Tools: current
    #

    def resolve_permissions(self, scope_id=1, auth_data=None) -> list:
        """ Resolve current permissions """
        # Public: no permissions
        return list()
        if auth_data is None:
            auth_data = flask.g.auth
        #
        if auth_data.type == "user":
            return self.get_user_permissions(auth_data.id, scope_id)
        elif auth_data.type == "token":
            return self.get_token_permissions(auth_data.id, scope_id)
        else:
            # Public: no permissions
            return list()

    def current_user(self, auth_data=None) -> dict:
        """ Get current user """
        # Public
        return {
            "id": None, "email": "public@platform.user", "name": "Public"
        }
        if auth_data is None:
            auth_data = flask.g.auth
        #
        if auth_data.type == "user":
            return self.get_user(id=auth_data.id)
        elif auth_data.type == "token":
            token = self.get_token(id=auth_data.id)
            return self.get_user(id=token["user_id"])
        else:
            # Public
            return {
                "id": None, "email": "public@platform.user", "name": "Public"
            }

    #
    # Tools: SIO
    #

    def sio_make_auth_data(self, environ):
        """ SIO: make auth data """
        auth_data = Holder()
        #
        auth_data.type = environ.get("HTTP_X_AUTH_TYPE", "public")
        auth_data.id = environ.get("HTTP_X_AUTH_ID", "-")
        auth_data.reference = environ.get("HTTP_X_AUTH_REFERENCE", "-")
        #
        try:
            auth_data.id = int(auth_data.id)
        except:
            auth_data.id = "-"
        #
        return auth_data

    #
    # Tools: slot
    #

    def make_request_state(self):
        """ Make request state snapshot for slots """
        state = Holder()
        #
        state.auth = flask.g.auth
        #
        state.request = Holder()
        state.request.args = dict(flask.request.args)
        #
        return state
