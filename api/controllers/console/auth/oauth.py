import logging
from datetime import datetime, timezone
from typing import Optional

import requests
from flask import current_app, redirect, request
from flask_restful import Resource

from constants.languages import languages
from extensions.ext_database import db
from libs.oauth import GitHubOAuth, GoogleOAuth, OAuthUserInfo
from models.account import Account, AccountStatus
from services.account_service import AccountService, RegisterService, TenantService

from .. import api

'''
我想知道这个文件是干什么用的，每个函数的功能是怎样的

这个文件 controllers/console/auth/oauth.py 主要处理 OAuth 登录和回调的相关逻辑。以下是每个函数和类的功能：
1. get_oauth_providers 函数:
该函数在 Flask 应用的上下文中创建并返回一个包含 GitHub 和 Google OAuth 提供者的字典。
2. OAuthLogin 类:
这是一个 Flask-RESTful 资源类，处理 OAuth 登录请求。
get 方法根据提供者（provider）获取相应的 OAuth 提供者，并生成授权 URL，然后重定向用户到该 URL 进行 OAuth 授权。
3. OAuthCallback 类:
这是另一个 Flask-RESTful 资源类，处理 OAuth 授权后的回调请求。
get 方法处理 OAuth 回调，获取授权码，交换访问令牌，获取用户信息，并根据用户信息生成或更新账户，最后重定向用户到应用的主页面。
4. _get_account_by_openid_or_email 函数:
根据提供者和用户信息中的 OpenID 或邮箱查找账户。
5. _generate_account 函数:
根据提供者和用户信息生成或更新账户。
如果账户不存在，则创建新账户，并设置用户的界面语言。
将账户与 OAuth 提供者进行关联。
6. API 路由:
api.add_resource(OAuthLogin, '/oauth/login/<provider>')：为 OAuth 登录添加路由。
api.add_resource(OAuthCallback, '/oauth/authorize/<provider>')：为 OAuth 回调添加路由。
这个文件的主要目的是处理 OAuth 登录流程，包括重定向到 OAuth 提供者进行授权、处理授权回调、获取用户信息、生成或更新用户账户，并最终将用户重定向回应用的主页面。
'''

def get_oauth_providers():
    with current_app.app_context():
        github_oauth = GitHubOAuth(client_id=current_app.config.get('GITHUB_CLIENT_ID'),
                                   client_secret=current_app.config.get(
                                       'GITHUB_CLIENT_SECRET'),
                                   redirect_uri=current_app.config.get(
                                       'CONSOLE_API_URL') + '/console/api/oauth/authorize/github')

        google_oauth = GoogleOAuth(client_id=current_app.config.get('GOOGLE_CLIENT_ID'),
                                   client_secret=current_app.config.get(
                                       'GOOGLE_CLIENT_SECRET'),
                                   redirect_uri=current_app.config.get(
                                       'CONSOLE_API_URL') + '/console/api/oauth/authorize/google')

        OAUTH_PROVIDERS = {
            'github': github_oauth,
            'google': google_oauth
        }
        return OAUTH_PROVIDERS


class OAuthLogin(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
            print(vars(oauth_provider))
        if not oauth_provider:
            return {'error': 'Invalid provider'}, 400

        auth_url = oauth_provider.get_authorization_url()
        return redirect(auth_url)


class OAuthCallback(Resource):
    def get(self, provider: str):
        OAUTH_PROVIDERS = get_oauth_providers()
        with current_app.app_context():
            oauth_provider = OAUTH_PROVIDERS.get(provider)
        if not oauth_provider:
            return {'error': 'Invalid provider'}, 400

        code = request.args.get('code')
        try:
            token = oauth_provider.get_access_token(code)
            user_info = oauth_provider.get_user_info(token)
        except requests.exceptions.HTTPError as e:
            logging.exception(
                f"An error occurred during the OAuth process with {provider}: {e.response.text}")
            return {'error': 'OAuth process failed'}, 400

        account = _generate_account(provider, user_info)
        # Check account status
        if account.status == AccountStatus.BANNED.value or account.status == AccountStatus.CLOSED.value:
            return {'error': 'Account is banned or closed.'}, 403

        if account.status == AccountStatus.PENDING.value:
            account.status = AccountStatus.ACTIVE.value
            account.initialized_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db.session.commit()

        TenantService.create_owner_tenant_if_not_exist(account)

        AccountService.update_last_login(account, request)

        token = AccountService.get_account_jwt_token(account)

        return redirect(f'{current_app.config.get("CONSOLE_WEB_URL")}?console_token={token}')


def _get_account_by_openid_or_email(provider: str, user_info: OAuthUserInfo) -> Optional[Account]:
    account = Account.get_by_openid(provider, user_info.id)

    if not account:
        account = Account.query.filter_by(email=user_info.email).first()

    return account


def _generate_account(provider: str, user_info: OAuthUserInfo):
    # Get account by openid or email.
    account = _get_account_by_openid_or_email(provider, user_info)

    if not account:
        # Create account
        account_name = user_info.name if user_info.name else 'Dify'
        account = RegisterService.register(
            email=user_info.email,
            name=account_name,
            password=None,
            open_id=user_info.id,
            provider=provider
        )

        # Set interface language
        preferred_lang = request.accept_languages.best_match(languages)
        if preferred_lang and preferred_lang in languages:
            interface_language = preferred_lang
        else:
            interface_language = languages[0]
        account.interface_language = interface_language
        db.session.commit()

    # Link account
    AccountService.link_account_integrate(provider, user_info.id, account)

    return account


api.add_resource(OAuthLogin, '/oauth/login/<provider>')
api.add_resource(OAuthCallback, '/oauth/authorize/<provider>')
