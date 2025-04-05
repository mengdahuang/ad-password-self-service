import json
import logging
import os
import traceback

from django.shortcuts import render
from utils.ad_ops import AdOps
import urllib.parse as url_encode
from utils.format_username import format2username, get_user_is_active, get_email_from_userinfo
from .form import CheckForm
from .utils import code_2_user_detail, ops_account
from utils.tracecalls import decorator_logger
from pwdselfservice import cache_storage

APP_ENV = os.getenv('APP_ENV')
if APP_ENV == 'dev':
    from conf.local_settings_dev import INTEGRATION_APP_TYPE, DING_MO_APP_ID, WEWORK_CORP_ID, WEWORK_AGENT_ID, HOME_URL, \
        DING_CORP_ID, TITLE
else:
    from conf.local_settings import INTEGRATION_APP_TYPE, DING_MO_APP_ID, WEWORK_CORP_ID, WEWORK_AGENT_ID, HOME_URL, \
        DING_CORP_ID, TITLE

msg_template = 'messages.html'
logger = logging.getLogger(__name__)


class PARAMS(object):
    if INTEGRATION_APP_TYPE == 'DING':
        corp_id = DING_CORP_ID
        app_id = DING_MO_APP_ID
        agent_id = None
        AUTH_APP = '钉钉'
        from utils.dingding_ops import DingDingOps
        ops = DingDingOps()
    elif INTEGRATION_APP_TYPE == 'WEWORK':
        corp_id = None
        app_id = WEWORK_CORP_ID
        agent_id = WEWORK_AGENT_ID
        AUTH_APP = '微信'
        from utils.wework_ops import WeWorkOps
        ops = WeWorkOps()


scan_params = PARAMS()
_ops = scan_params.ops


@decorator_logger(logger, log_head='Request', pretty=True, indent=2, verbose=1)
def auth(request):
    """
    授权页面
    """
    redirect_to = request.GET.get('redirect', 'resetPassword')
    
    context = {
        'global_title': TITLE,
        'app_type': APP_TYPE,
        'corp_id': WEWORK_CORP_ID if APP_TYPE == 'WEWORK' else DING_CORP_ID,
        'agent_id': WEWORK_AGENT_ID if APP_TYPE == 'WEWORK' else DING_AGENT_ID,
        'app_id': WEWORK_CORP_ID if APP_TYPE == 'WEWORK' else DING_CORP_ID,
        'redirect_url': request.build_absolute_uri(f'/{redirect_to}'),
    }
    return render(request, 'auth.html', context)

    home_url = '%s://%s' % (request.scheme, HOME_URL)
    corp_id = scan_params.corp_id
    app_id = scan_params.app_id
    agent_id = scan_params.agent_id
    scan_app = scan_params.AUTH_APP
    redirect_url = url_encode.quote(home_url + '/resetPassword')
    app_type = INTEGRATION_APP_TYPE
    global_title = TITLE
    if request.method == 'GET':
        return render(request, 'auth.html', locals())
    else:
        logger.error('[异常]  请求方法：%s，请求路径%s' % (request.method, request.path))


@decorator_logger(logger, log_head='Request', pretty=True, indent=2, verbose=1)
def index(request):
    home_url = '%s://%s' % (request.scheme, HOME_URL)
    scan_app = scan_params.AUTH_APP
    global_title = TITLE

    if request.method == 'GET':
        return render(request, 'index.html', locals())

    elif request.method == 'POST':
        # 对前端提交的数据进行二次验证，防止恶意提交简单密码或篡改账号。
        check_form = CheckForm(request.POST)
        if check_form.is_valid():
            form_obj = check_form.cleaned_data
            username = form_obj.get("username")
            old_password = form_obj.get("old_password")
            new_password = form_obj.get("new_password")
        else:
            _msg = check_form
            logger.error('[异常]  请求方法：%s，请求路径：%s，错误信息：%s' % (request.method, request.path, _msg))
            context = {
                'global_title': TITLE,
                'msg': _msg,
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)
        # 格式化用户名
        _, username = format2username(username)
        if _ is False:
            context = {
                'global_title': TITLE,
                'msg': username,
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)
        # 检测账号状态
        auth_status, auth_result = AdOps().ad_auth_user(username=username, password=old_password)
        if not auth_status:
            context = {
                'global_title': TITLE,
                'msg': str(auth_result),
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)
        return ops_account(AdOps(), request, msg_template, home_url, username, new_password)
    else:
        context = {
            'global_title': TITLE,
            'msg': "不被接受的认证信息，请重新尝试认证授权。",
            'button_click': "window.location.href='%s'" % '/auth',
            'button_display': "重新认证授权"
        }
        return render(request, msg_template, context)


@decorator_logger(logger, log_head='Request', pretty=True, indent=2, verbose=1)
def reset_password(request):
    """
    钉钉扫码并验证信息通过之后，在重置密码页面将用户账号进行绑定
    :param request:
    :return:
    """
    home_url = '%s://%s' % (request.scheme, HOME_URL)
    if request.method == 'GET':
        code = request.GET.get('code')
        username = request.GET.get('username')
        # 如果从GET路径中提取到username、code，并且在缓存中存在username对应的code值，说明已经认证过
        if username and code and cache_storage.get(username) == code:
            context = {
                'global_title': TITLE,
                'username': username,
                'code': code,
            }
            return render(request, 'reset_password.html', context)
        # 否则就是第一次认证，用code换取用户信息
        else:
            if not code:
                context = {
                    'global_title': TITLE,
                    'msg': "临时授权码己失效，请尝试重新认证授权...",
                    'button_click': "window.location.href='%s'" % '/auth',
                    'button_display': "重新认证授权"
                }
                return render(request, msg_template, context)
            try:
                _status, user_id, user_info = code_2_user_detail(_ops, home_url, code)
                if not _status:
                    return render(request, msg_template, user_id)
                # 账号在企业微信或钉钉中是否是激活的
                _, res = get_user_is_active(user_info)
                if not _:
                    context = {
                        'global_title': TITLE,
                        'msg': '当前扫码的用户未激活或可能己离职，用户信息如下：%s' % user_info,
                        'button_click': "window.location.href='%s'" % home_url,
                        'button_display': "返回主页"
                    }
                    return render(request, msg_template, context)

                # 通过user_info拿到用户邮箱，并格式化为username
                _, email = get_email_from_userinfo(user_info)
                if not _:
                    context = {
                        'global_title': TITLE,
                        'msg': email,
                        'button_click': "window.location.href='%s'" % '/auth',
                        'button_display': "重新认证授权"
                    }
                    return render(request, msg_template, context)
                _, username = format2username(email)
                if _ is False:
                    context = {
                        'global_title': TITLE,
                        'msg': username,
                        'button_click': "window.location.href='%s'" % '/auth',
                        'button_display': "重新认证授权"
                    }
                    return render(request, msg_template, context)
                if username:
                    cache_storage.set(username, code, ttl=300)
                    context = {
                        'global_title': TITLE,
                        'username': username,
                        'code': code,
                    }
                    return render(request, 'reset_password.html', context)
                else:
                    context = {
                        'global_title': TITLE,
                        'msg': "{}，您好，企业{}中未能找到您账号的邮箱配置，请联系HR完善信息。".format(
                            user_info.get('name'), scan_params.AUTH_APP),
                        'button_click': "window.location.href='%s'" % '/auth',
                        'button_display': "重新认证授权"
                    }
                    return render(request, msg_template, context)

            except Exception as callback_e:
                context = {
                    'global_title': TITLE,
                    'msg': "错误[%s]，请与管理员联系." % str(callback_e),
                    'button_click': "window.location.href='%s'" % home_url,
                    'button_display': "返回主页"
                }
                logger.error('[异常] ：%s' % str(callback_e))
                return render(request, msg_template, context)

    # 重置密码页面，输入新密码后点击提交
    elif request.method == 'POST':
        username = request.POST.get('username')
        code = request.POST.get('code')
        if username and code and cache_storage.get(username) == code:
            _new_password = request.POST.get('new_password').strip()
            try:
                return ops_account(ad_ops=AdOps(), request=request, msg_template=msg_template, home_url=home_url,
                                   username=username, new_password=_new_password)
            except Exception as reset_e:
                context = {
                    'global_title': TITLE,
                    'msg': "错误[%s]，请与管理员联系." % str(reset_e),
                    'button_click': "window.location.href='%s'" % home_url,
                    'button_display': "返回主页"
                }
                logger.error('[异常] ：%s' % str(reset_e))
                return render(request, msg_template, context)
        else:
            context = {
                'global_title': TITLE,
                'msg': "认证已经失效，可尝试从重新认证授权。",
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)


@decorator_logger(logger, log_head='Request', pretty=True, indent=2, verbose=1)
def unlock_account(request):
    """
    解锁账号
    :param request:
    :return:
    """
    home_url = '%s://%s' % (request.scheme, HOME_URL)

    if request.method == 'GET':
        code = request.GET.get('code')
        username = request.GET.get('username')
        if username and code and cache_storage.get(username) == code:
            context = {
                'global_title': TITLE,
                'username': username,
                'code': code,
            }
            return render(request, 'unlock.html', context)
        else:
            context = {
                'global_title': TITLE,
                'msg': "{}，您好，当前会话可能已经过期，请再试一次吧。".format(username),
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)

    if request.method == 'POST':
        username = request.POST.get('username')
        code = request.POST.get('code')
        if username and code and cache_storage.get(username) == code:
            try:
                return ops_account(AdOps(), request, msg_template, home_url, username, None)
            except Exception as reset_e:
                context = {
                    'global_title': TITLE,
                    'msg': "错误[%s]，请与管理员联系." % str(reset_e),
                    'button_click': "window.location.href='%s'" % home_url,
                    'button_display': "返回主页"
                }
                logger.error('{}' .format(traceback.format_exc()))
                return render(request, msg_template, context)
        else:
            context = {
                'global_title': TITLE,
                'msg': "认证已经失效，请尝试从重新进行认证授权。",
                'button_click': "window.location.href='%s'" % '/auth',
                'button_display': "重新认证授权"
            }
            return render(request, msg_template, context)


@decorator_logger(logger, log_head='Request', pretty=True, indent=2, verbose=1)
def messages(request):
    _msg = request.GET.get('msg')
    button_click = request.GET.get('button_click')
    button_display = request.GET.get('button_display')
    context = {
        'global_title': TITLE,
        'msg': _msg,
        'button_click': button_click,
        'button_display': button_display
    }
    return render(request, msg_template, context)


def chat_page(request):
    """
    聊天页面，需要企业微信授权
    """
    context = {
        'global_title': TITLE,
        'app_type': APP_TYPE,
    }
    
    # 获取code参数
    code = request.GET.get('code')
    if not code:
        # 如果没有code，重定向到授权页面
        return redirect('/auth?redirect=chat')
    
    # 使用企业微信API获取用户信息
    wework = WeWorkOps()
    status, user_id, user_info = wework.get_user_detail(code, '/')
    
    if not status:
        # 如果获取用户信息失败，显示错误信息
        if isinstance(user_id, dict):
            context.update(user_id)
            return render(request, 'messages.html', context)
        context.update({
            'msg': '获取用户信息失败',
            'button_click': "window.location.href='/'",
            'button_display': "返回主页"
        })
        return render(request, 'messages.html', context)
    
    # 生成一个新的chatId
    import uuid
    chat_id = f"chat_{uuid.uuid4().hex}"
    
    # 将用户信息和chatId添加到上下文
    context.update({
        'userId': user_id,
        'chatId': chat_id,
        'code': code,
        'username': user_info.get('name', user_id)
    })
    
    return render(request, 'chat.html', context)

@require_POST
@csrf_exempt
def chat_send(request):
    """
    处理聊天消息发送
    """
    try:
        message = request.POST.get('message')
        chat_id = request.POST.get('chatId')
        user_id = request.POST.get('userId')
        
        if not all([message, chat_id, user_id]):
            return JsonResponse({
                'success': False,
                'message': '参数不完整'
            })
        
        # 调用FastGPT API
        headers = {
            'Authorization': f'Bearer {FASTGPT_API_KEY}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'chatId': chat_id,
            'stream': False,
            'detail': False,
            'variables': {
                'userId': user_id
            },
            'messages': [
                {
                    'role': 'user',
                    'content': message
                }
            ]
        }
        
        response = requests.post(
            f'{FASTGPT_API_URL}/api/v1/chat/completions',
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            data = response.json()
            content = data['choices'][0]['message']['content']
            
            return JsonResponse({
                'success': True,
                'data': {
                    'content': content
                }
            })
        else:
            return JsonResponse({
                'success': False,
                'message': f'API请求失败: {response.status_code}'
            })
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'处理请求时出错: {str(e)}'
        })
