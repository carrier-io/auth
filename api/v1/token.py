from flask import g, make_response
from flask_restful import Resource
from pylon.core.tools import log

from tools import auth


class API(Resource):
    def __init__(self, module):
        self.module = module

    # @auth.decorators.check_api(['global_view'])
    def get(self, user_id: int = 1):

        # user_id = g.auth.id # todo: remove

        all_tokens = auth.list_tokens(user_id)
        #
        if len(all_tokens) < 1:
            token_id = auth.add_token(
                user_id, "api",
                # expires=datetime.datetime.now()+datetime.timedelta(seconds=30),
            )
        else:
            token_id = all_tokens[0]["id"]
        #
        current_permissions = auth.resolve_permissions(
            1, auth_data=g.auth
        )
        #
        for permission in current_permissions:
            try:
                auth.add_token_permission(token_id, 1, permission)
            except:  # pylint: disable=W0702
                pass
        #
        token = auth.encode_token(token_id)
        log.warning('Token for user %s : %s', user_id, token)
        return make_response(token, 200)