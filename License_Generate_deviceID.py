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
import logging
# 日志名称
if not os.path.exists('log'):
    os.makedirs('log')
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"log\\log_license_generate_device_id_{timestamp}.txt"

# 自定义 Logger
logger = logging.getLogger("MyLogger")
logger.setLevel(logging.DEBUG)  # 捕获所有级别

# 1️⃣ 文件输出（保存所有日志）
file_handler = logging.FileHandler(log_file, encoding="utf-8")
file_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)
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
    logger.debug(f"get_device_raw_data结果获取: {data}")
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
    #ctypes.windll.user32.MessageBoxW(0, f"Device ID 已写入: {path}", "成功", 0)
    logger.info(f"Device ID 已写入: {path}")

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
    #ctypes.windll.user32.MessageBoxW(0, f"License 已生成: {out_path}", "成功", 0)
    logger.info(f"License 已生成: {out_path}")
    return out_path



# ------------------------
# 示例：发放端（生成 device id -> 管理员收到 device id -> 生成 license）
# ------------------------
def example_generate_flow( device_id_save_path= None):
    try:
        # 生产端或目标机器上运行（注意：如果你需要 deterministic device_id，不要包含 timestamp）
        raw = get_device_raw_data(extra=None)
        # remove timestamp to make device id deterministic (if you require deterministic behavior)
        if "timestamp" in raw:
            raw.pop("timestamp", None)
        device_id_token = FERNET_DEVICE.encrypt(json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        device_id_str = device_id_token.decode("utf-8")
        # 可将 device_id_str 发送给许可管理员（或写入文件）
        if device_id_save_path is not None:
            save_path=device_id_save_path
        else:
            save_path=DEVICE_ID_FILE
            
        with open(save_path, "w", encoding="utf-8") as f:        
            f.write(device_id_str)
        #ctypes.windll.user32.MessageBoxW(0, f"device_id 已导出: {save_path}", "提示", 0)
        logger.debug(f"device_id 已导出: {save_path}")
        # 管理端读取 device_id_str，然后调用 generate_license_from_device_id(...)
        # 例如:
        # generate_license_from_device_id(device_id_str, user="Alice", expire_date="2026-12-31")
        logger.debug(f"device_id_str={device_id_str}")
        return True
    except Exception as e:
        #ctypes.windll.user32.MessageBoxW(0, f"{e}", "错误", 0)
        logger.error(f"{e}")
        return False
# ------------------------
# CLI / 调用示例
# ------------------------
if __name__ == "__main__":
    if len(sys.argv) >= 2:
        result=example_generate_flow(sys.argv[1])
    else:
        result=example_generate_flow()
        
    if result == True:
        sys.exit(0)  # 通过
    else:
        sys.exit(1)  # 失败

