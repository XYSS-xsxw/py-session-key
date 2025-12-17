#!/usr/bin/env python3
""" Flask Session Cookie Decoder/Encoder """

# standard imports
import sys
import zlib
import ast
import hmac
import hashlib
from itsdangerous import base64_decode, BadSignature, SignatureExpired

# 修正版本判断
if sys.version_info[0] < 3:  # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4:  # >= 3.0 && < 3.4
    from abc import ABCMeta
else:  # >= 3.4
    from abc import ABC

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface


class MockApp(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.config = {"SECRET_KEY_FALLBACKS": None}


# 提取公共方法，避免重复
def encode_impl(secret_key, session_cookie_structure):
    """ Encode a Flask session cookie """
    try:
        app = MockApp(secret_key)
        session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
        si = SecureCookieSessionInterface()
        s = si.get_signing_serializer(app)
        return s.dumps(session_cookie_structure)
    except Exception as e:
        return f"[Encoding error] {e}"


def decode_impl(session_cookie_value, secret_key=None):
    """ Decode a Flask cookie """
    try:
        if secret_key is None:
            compressed = False
            payload = session_cookie_value

            if payload.startswith('.'):
                compressed = True
                payload = payload[1:]

            data = payload.split(".")[0]
            data = base64_decode(data)
            if compressed:
                data = zlib.decompress(data)
            return data
        else:
            app = MockApp(secret_key)
            si = SecureCookieSessionInterface()
            s = si.get_signing_serializer(app)
            return s.loads(session_cookie_value)
    except Exception as e:
        return f"[Decoding error] {e}"

#利用不成功就会报错的原理
def bp_impl(session_cookie_value, file_path):
    """ Brute force secret key """
    try:
        with open(file_path, 'r') as f:
            for line in f:
                secret_key = line.strip()  # 去除换行符
                if not secret_key:  # 跳过空行
                    continue
                try:
                    app = MockApp(secret_key)
                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)
                    # 尝试解码，成功则返回密钥
                    s.loads(session_cookie_value)
                    return secret_key  # 找到正确的密钥
                except (BadSignature, SignatureExpired):
                    continue  # 密钥错误，继续尝试
                except Exception:
                    continue  # 其他错误，继续尝试
        return None  # 没有找到正确的密钥
    except FileNotFoundError:
        return f"[Error] File not found: {file_path}"
    except Exception as e:
        return f"[BP error] {e}"



class FSCM(ABC):
    @staticmethod
    def encode(secret_key, session_cookie_structure):
        return encode_impl(secret_key, session_cookie_structure)

    @staticmethod
    def decode(session_cookie_value, secret_key=None):
        return decode_impl(session_cookie_value, secret_key)

    @staticmethod
    def bp(session_cookie_value, file_path):
        return bp_impl(session_cookie_value, file_path)

if __name__ == "__main__":
    # Args are only relevant for __main__ usage
    parser = argparse.ArgumentParser(
        description='Flask Session Cookie Decoder/Encoder/BruteForce',
        epilog="Author : Wilson Sumanang, Alexandre ZANNI")

    # prepare sub commands
    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

    # encode command
    parser_encode = subparsers.add_parser('encode', help='encode session cookie')
    parser_encode.add_argument('-s', '--secret-key', metavar='<string>',
                               help='Secret key', required=True)
    parser_encode.add_argument('-t', '--cookie-structure', metavar='<string>',
                               help='Session cookie structure', required=True)

    # decode command
    parser_decode = subparsers.add_parser('decode', help='decode session cookie')
    parser_decode.add_argument('-s', '--secret-key', metavar='<string>',
                               help='Secret key', required=False)
    parser_decode.add_argument('-c', '--cookie-value', metavar='<string>',
                               help='Session cookie value', required=True)

    # bp command (新增，不覆盖decode)
    parser_bp = subparsers.add_parser('bp', help='brute force secret key')
    parser_bp.add_argument('-f', '--file', metavar='<path>',
                           help='Secret key dictionary file', required=True)
    parser_bp.add_argument('-c', '--cookie-value', metavar='<string>',
                           help='Session cookie value', required=True)

    # get args
    args = parser.parse_args()

    # 处理命令
    if not hasattr(args, 'subcommand'):
        parser.print_help()
        sys.exit(1)

    if args.subcommand == 'encode':
        if args.secret_key and args.cookie_structure:
            result = FSCM.encode(args.secret_key, args.cookie_structure)
            print(result)

    elif args.subcommand == 'decode':
        if args.secret_key and args.cookie_value:
            result = FSCM.decode(args.cookie_value, args.secret_key)
            print(result)
        elif args.cookie_value:
            result = FSCM.decode(args.cookie_value)
            print(result)

    elif args.subcommand == 'bp':
        if args.file and args.cookie_value:
            result = FSCM.bp(args.cookie_value, args.file)
            if result and not result.startswith("[Error]") and not result.startswith("[BP error]"):
                print(f"成功爆破密钥: {result}")
            else:
                print(f"{result or '字典里面不存在密钥'}")
