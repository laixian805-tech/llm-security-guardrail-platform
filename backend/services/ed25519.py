"""RFC 8032 Ed25519 验签（纯标准库实现，无外部密码学依赖）。

只实现验签与公钥/签名格式校验：控制面不持有、不生成任何发布方私钥，
只存发布方登记的 32 字节 Ed25519 公钥，对 content_hash 做确定性验签。
"""

from __future__ import annotations

import base64
import hashlib
import binascii

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

_BY = (4 * pow(5, -1, _P)) % _P
_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_B = (_BX % _P, _BY % _P, 1, (_BX * _BY) % _P)
_NEUTRAL = (0, 1, 1, 0)


def _decode_bytes(raw: str, expected_len: int) -> bytes | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if len(text) == expected_len * 2 and all(c in "0123456789abcdefABCDEF" for c in text):
        return bytes.fromhex(text)
    padded = text + ("=" * ((4 - len(text) % 4) % 4))
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            data = decoder(padded, validate=True)
            if len(data) == expected_len:
                return data
        except (binascii.Error, ValueError):
            continue
    return None


def parse_public_key(raw: str) -> bytes | None:
    """解析并校验 32 字节 Ed25519 公钥（支持 64 位 hex 或 base64），返回原始字节或 None。"""
    data = _decode_bytes(raw, 32)
    if data is None or _point_decompress(data) is None:
        return None
    return data


def parse_signature(raw: str) -> bytes | None:
    """解析 64 字节 Ed25519 签名（支持 128 位 hex 或 base64），返回原始字节或 None。"""
    return _decode_bytes(raw, 64)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    if x2 == 0:
        return 0 if sign == 0 else None
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = (x * _I) % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _point_decompress(data: bytes) -> tuple[int, int, int, int] | None:
    if len(data) != 32:
        return None
    raw_y = int.from_bytes(data, "little")
    sign = (raw_y >> 255) & 1
    y = raw_y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def _point_add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e = (b - a) % _P
    f = (d - c) % _P
    g = (d + c) % _P
    h = (b + a) % _P
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _point_mul(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    res = _NEUTRAL
    acc = point
    k = scalar
    while k > 0:
        if k & 1:
            res = _point_add(res, acc)
        acc = _point_add(acc, acc)
        k >>= 1
    return res


def _point_equal(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """按 RFC 8032 严格校验 Ed25519 签名。"""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point = _point_decompress(public_key)
    r_bytes = signature[:32]
    r_point = _point_decompress(r_bytes)
    s_int = int.from_bytes(signature[32:], "little")
    if a_point is None or r_point is None or s_int >= _L:
        return False
    # Reject identity and all cofactor-8 small-order torsion points on A and R.
    if _point_equal(_point_mul(8, a_point), _NEUTRAL) or _point_equal(_point_mul(8, r_point), _NEUTRAL):
        return False
    h = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    lhs = _point_mul(s_int, _B)
    rhs = _point_add(r_point, _point_mul(h, a_point))
    return _point_equal(lhs, rhs)
