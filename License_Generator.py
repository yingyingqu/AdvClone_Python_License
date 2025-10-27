# adv_license.py
import uuid
import hashlib
import base64
import json
import os
import sys
from datetime import datetime
import ctypes

from cryptography.fernet import Fernet

# ------------------------
# 配置（请生产环境妥善保管）
# ------------------------
# 用于生成 Device ID 的密钥字符串（用于对设备数据第一次加密）
SECRET_STR_DEVICE = "Advclone2025@AdvantechDeviceKey!@#123"

# 用于生成 License 的密钥字符串（用于对 Device ID 第二次加密）
SECRET_STR_LICENSE = "Advclone2025@AdvantechLicenseKey$%^456"

# 输出文件名
DEVICE_ID_FILE = "device_id.txt"   # 可选：将 device id 导出到文本以便发放时使用
LICENSE_FILE = "license.lic"

# ------------------------
# 工具：从字符串派生 Fernet key
# ------------------------
def derive_fernet_key(secret_str: str) -> bytes:
    """从任意字符串安全派生 32 字节，然后 base64 urlsafe 编码为 Fernet key"""
    raw = hashlib.sha256(secret_str.encode("utf-8")).digest()  # 32 bytes
    return base64.urlsafe_b64encode(raw)

# 生成两个 cipher 实例
FERNET_DEVICE = Fernet(derive_fernet_key(SECRET_STR_DEVICE))
FERNET_LICENSE = Fernet(derive_fernet_key(SECRET_STR_LICENSE))

# ------------------------
# 获取设备原始数据（可扩展）
# ------------------------
def get_device_raw_data(extra: dict = None) -> dict:
    """
    返回可以用来标识设备的原始数据字典
    默认包含 MAC 地址和主机名，extra 可加入序列号、CPU id 等（如有）。
    """
    mac_int = uuid.getnode()
    mac_str = ':'.join(("%012X" % mac_int)[i:i+2] for i in range(0, 12, 2))
    hostname = os.environ.get("COMPUTERNAME") or os.uname().nodename if hasattr(os, "uname") else ""
    '''
    data = {
        "mac": mac_str,
        "hostname": hostname,
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")  # 生成 Device ID 时的时间戳（可选）
    }
    '''
    data = {
        "mac": mac_str
    }
    if extra:
        data.update(extra)
    return data

# ------------------------
# 1) 生成 Device ID（对设备数据进行第一次加密）
# ------------------------
def generate_device_id(extra: dict = None) -> str:
    """
    将设备原始数据 JSON 加密，返回 URL-safe 的 Device ID 字符串。
    这个 Device ID 可导出给许可管理员用于生成 license。
    """
    raw = get_device_raw_data(extra)
    json_bytes = json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    token = FERNET_DEVICE.encrypt(json_bytes)  # bytes
    device_id = token.decode("utf-8")  # 可安全保存/传输
    return device_id

def export_device_id_file(path: str = DEVICE_ID_FILE, extra: dict = None):
    did = generate_device_id(extra)
    with open(path, "w", encoding="utf-8") as f:
        f.write(did)
    ctypes.windll.user32.MessageBoxW(0, f"Device ID 已写入: {path}", "成功", 0)

# ------------------------
# 2) 由 Device ID 生成 License（对 Device ID 二次加密，并可加入到期/用户信息）
# ------------------------
def generate_license_from_device_id(device_id: str, user: str, expire_date: str, out_path: str = LICENSE_FILE):
    """
    device_id: 前面生成的字符串（必须）
    user: 授权用户名
    expire_date: 格式 'YYYY-MM-DD'
    输出 license 文件（二进制），内容为对包含 device_id 的 JSON 再次加密的 token。
    """
    '''
    payload = {
        "device_id": device_id,
        "user": user,
        "expire": expire_date,
        "issued": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    '''
    payload = {
        "device_id": device_id
    }
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    license_token = FERNET_LICENSE.encrypt(plaintext)  # bytes
    with open(out_path, "wb") as f:
        f.write(license_token)
    # GUI 提示（适合无控制台 exe）
    ctypes.windll.user32.MessageBoxW(0, f"License 已生成: {out_path}", "成功", 0)
    return out_path

# ------------------------
# 验证流程（客户端）
# ------------------------
def verify_license(license_path: str = LICENSE_FILE) -> bool:
    """
    验证 license 文件：
      1. 解密 license -> 得到内部的 device_id
      2. 重新在本机生成 device_id（注意生成时的原始数据必须一致——如果 Device ID 中包含 timestamp 等会导致不匹配）
      3. 比较两者是否匹配，并检查到期时间
    注意：这里的策略假定 Device ID 是 deterministic 的（即相同设备使用相同 raw data -> device id）。
    如果 generate_device_id 在生成时包含时间戳等变量字段，验证将失败 —— 所以发放端和验证端应使用相同策略。
    """
    if not os.path.exists(license_path):
        ctypes.windll.user32.MessageBoxW(0, "License 文件不存在！", "错误", 0)
        return False

    try:
        with open(license_path, "rb") as f:
            license_token = f.read()
        # 解密 license（得到内部 payload）
        plaintext = FERNET_LICENSE.decrypt(license_token)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"License 解密失败或已被篡改！\n{e}", "错误", 0)
        return False

    # 从 license 里取得 device_id
    device_id_in_license = payload.get("device_id")
    if not device_id_in_license:
        ctypes.windll.user32.MessageBoxW(0, "License 内容不包含 device_id！", "错误", 0)
        return False

    # 重新生成本机的 device_id -- **注意**：生成器必须是 deterministic（不能包含生成时的 timestamp）
    # 推荐做法：在生成 Device ID 时，不要加入每次都会变化的字段（例如 timestamp）。
    # 如果你用了 timestamp，请改为将 timestamp 放到 license payload，而非 device 原始数据。
    # 这里我们重新生成 device id using deterministic raw data (mac + hostname)
    try:
        # IMPORTANT: to be deterministic, generate_device_id must be called WITHOUT timestamp in raw data.
        # So we call a variant that excludes timestamp.
        local_raw = get_device_raw_data(extra=None)
        # remove timestamp field for deterministic comparison if generate_device_id used extra=None originally
        if "timestamp" in local_raw:
            del local_raw["timestamp"]
        # create deterministic device id generator inline:
        json_bytes = json.dumps(local_raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        local_device_token = FERNET_DEVICE.encrypt(json_bytes)  # This would produce different token each run due to Fernet nonce
        # WARNING: Fernet includes random IV so tokens differ each encrypt -> cannot compare token strings directly!
        # Correct approach: do NOT compare encrypted tokens directly. Instead compare decrypted payloads.
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"本机 Device ID 生成失败：\n{e}", "错误", 0)
        return False

    # ==== CORRECT COMPARISON METHOD ====
    # Instead of comparing encrypted tokens (它们会因为随机 IV 而不同)，我们应当：
    #  - 解密 device_id_in_license（这是一个 Fernet token produced at device-side）得到内部原始 JSON
    #  - 重新构造本机的 raw data JSON（严格相同字段顺序和内容），然后直接比较 JSON 字符串或字典
    try:
        # device_id_in_license 是由 FERNET_DEVICE.encrypt(raw_json) 产生的 token
        decrypted_device_bytes = FERNET_DEVICE.decrypt(device_id_in_license.encode("utf-8"))
        device_data_from_license = json.loads(decrypted_device_bytes.decode("utf-8"))
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"无法解密 device_id（可能密钥不匹配或 device_id 被篡改）\n{e}", "错误", 0)
        return False

    # 构造本机 raw_data (deterministic) —— 注意：这里要和 generate_device_id 使用完全相同的字段集合与顺序
    # 推荐在生产中：不要在 raw data 中加入 timestamp；如果需要记录生成时间，把 issued 放到 license payload。
    '''
    local_raw_data = {
        "mac": get_device_raw_data().get("mac"),
        "hostname": get_device_raw_data().get("hostname")
    }
    '''
    local_raw_data = {
        "mac": get_device_raw_data().get("mac")     
    }
    # 如果发放端在生成 Device ID 时加入了额外字段（例如 serial），验证端也必须知道并提供相同字段。
    # 比较两个原始字典是否相同
    # Note: device_data_from_license may contain extra fields — do a subset compare
    # We'll check that mac and hostname match:
    if device_data_from_license.get("mac") != local_raw_data.get("mac") :
        ctypes.windll.user32.MessageBoxW(0, "License 与本机不匹配（MAC/Hostname 不同）", "错误", 0)
        return False
    '''
    # 检查到期
    expire_str = payload.get("expire")
    try:
        expire_date = datetime.strptime(expire_str, "%Y-%m-%d")
    except Exception:
        ctypes.windll.user32.MessageBoxW(0, "License 到期日期格式无效！", "错误", 0)
        return False

    if datetime.now() > expire_date:
        ctypes.windll.user32.MessageBoxW(0, "License 已过期！", "错误", 0)
        return False
    '''
    # 通过
    ctypes.windll.user32.MessageBoxW(0,
        f"License 验证通过！\n用户: {payload.get('user')}\n到期: {payload.get('expire')}",
        "成功", 0)
    return True

# ------------------------
# 示例：发放端（生成 device id -> 管理员收到 device id -> 生成 license）
# ------------------------
def example_generate_flow():
    # 生产端或目标机器上运行（注意：如果你需要 deterministic device_id，不要包含 timestamp）
    raw = get_device_raw_data(extra=None)
    # remove timestamp to make device id deterministic (if you require deterministic behavior)
    if "timestamp" in raw:
        raw.pop("timestamp", None)
    device_id_token = FERNET_DEVICE.encrypt(json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    device_id_str = device_id_token.decode("utf-8")
    # 可将 device_id_str 发送给许可管理员（或写入文件）
    with open(DEVICE_ID_FILE, "w", encoding="utf-8") as f:
        f.write(device_id_str)
    ctypes.windll.user32.MessageBoxW(0, f"device_id 已导出: {DEVICE_ID_FILE}", "提示", 0)
    # 管理端读取 device_id_str，然后调用 generate_license_from_device_id(...)
    # 例如:
    # generate_license_from_device_id(device_id_str, user="Alice", expire_date="2026-12-31")

# ------------------------
# CLI / 调用示例
# ------------------------
if __name__ == "__main__":
    # 下面演示如何使用（注释/取消注释相应行）
    # 1) 在目标设备上生成 device_id 并导出给管理员（发放方）
    #example_generate_flow()

    # 2) 管理员用 device_id 生成 license（假设 device_id 已复制到变量 device_id_str）
    device_id_str = open(DEVICE_ID_FILE, "r", encoding="utf-8").read().strip()
    generate_license_from_device_id(device_id_str, user="CustomerA", expire_date="2026-12-31", out_path=LICENSE_FILE)

