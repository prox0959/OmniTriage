"""
OmniTriage - Network & Peripheral Forensics Collector
Extracts Wi-Fi network profiles, USBSTOR connection history, and active network connections.
Author: Çınar (prox0959)
"""

import os
import socket
import winreg
import subprocess
import struct
from datetime import datetime

def parse_systemtime_bytes(b: bytes) -> str:
    """
    TR: Windows SYSTEMTIME binary yapısını (16 byte: Year, Month, DayOfWeek, Day, Hour, Min, Sec, MS) okur.
    Parses Windows 16-byte SYSTEMTIME structure into ISO string.
    """
    try:
        if len(b) >= 16:
            year, month, _, day, hour, minute, second, _ = struct.unpack("<8H", b[:16])
            if 1970 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
    except Exception:
        pass
    return "N/A"

def get_wifi_and_network_profiles() -> list:
    """
    TR: NetworkList\\Profiles altından önceden bağlanılan tüm Wi-Fi ve Ethernet ağlarının isimlerini çeker.
    Extracts historical Wi-Fi and Ethernet connection profiles from the Windows Registry.
    """
    profiles = []
    base_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path) as root_key:
            num_subkeys = winreg.QueryInfoKey(root_key)[0]
            for i in range(num_subkeys):
                guid = winreg.EnumKey(root_key, i)
                profile_path = f"{base_path}\\{guid}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profile_path) as pkey:
                        def qv(name):
                            try:
                                v, _ = winreg.QueryValueEx(pkey, name)
                                return v
                            except Exception:
                                return None

                        profile_name = qv("ProfileName")
                        name_type = qv("NameType") # 71 (0x47) = Wireless, 6 = Wired
                        created_bytes = qv("DateCreated")
                        connected_bytes = qv("DateLastConnected")

                        type_desc = "Wireless (Wi-Fi)" if name_type == 71 else ("Wired (Ethernet)" if name_type == 6 else "Unknown")
                        date_created = parse_systemtime_bytes(created_bytes) if isinstance(created_bytes, bytes) else "N/A"
                        date_connected = parse_systemtime_bytes(connected_bytes) if isinstance(connected_bytes, bytes) else "N/A"

                        if profile_name:
                            profiles.append({
                                "profile_name": profile_name,
                                "type": type_desc,
                                "date_created": date_created,
                                "date_last_connected": date_connected,
                                "guid": guid
                            })
                except Exception:
                    continue
    except Exception:
        pass

    # Fallback to netsh if registry was restricted or returned empty
    if not profiles:
        try:
            output = subprocess.check_output(["netsh", "wlan", "show", "profiles"], text=True, stderr=subprocess.DEVNULL, errors="ignore")
            for line in output.splitlines():
                if ":" in line and ("All User Profile" in line or "User Profile" in line or "Tüm Kullanıcı Profili" in line):
                    pname = line.split(":", 1)[1].strip()
                    if pname:
                        profiles.append({
                            "profile_name": pname,
                            "type": "Wireless (Wi-Fi)",
                            "date_created": "N/A (Standard Privileges)",
                            "date_last_connected": "N/A (Standard Privileges)",
                            "guid": "N/A"
                        })
        except Exception:
            pass

    return profiles

def get_usbstor_history() -> list:
    """
    TR: USBSTOR anahtarından bu bilgisayara daha önce takılmış tüm USB belleklerin marka, model ve seri numaralarını çıkarır.
    Extracts historical USB storage device connection artifacts (Vendor, Product ID, Serial number).
    """
    usb_devices = []
    base_usbstor = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_usbstor) as root_key:
            num_dev_keys = winreg.QueryInfoKey(root_key)[0]
            for i in range(num_dev_keys):
                dev_id = winreg.EnumKey(root_key, i)
                dev_path = f"{base_usbstor}\\{dev_id}"
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dev_path) as dev_key:
                        num_instances = winreg.QueryInfoKey(dev_key)[0]
                        for j in range(num_instances):
                            serial = winreg.EnumKey(dev_key, j)
                            instance_path = f"{dev_path}\\{serial}"
                            try:
                                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, instance_path) as inst_key:
                                    def qv(name):
                                        try:
                                            v, _ = winreg.QueryValueEx(inst_key, name)
                                            return v
                                        except Exception:
                                            return None
                                    friendly_name = qv("FriendlyName")
                                    mfg = qv("Mfg")
                                    usb_devices.append({
                                        "device_id": dev_id,
                                        "serial_number": serial,
                                        "friendly_name": friendly_name or dev_id,
                                        "manufacturer": mfg or "Generic"
                                    })
                            except Exception:
                                continue
                except Exception:
                    continue
    except Exception:
        pass

    # Mounted Devices volumes
    mounted = []
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices") as mkey:
            num_vals = winreg.QueryInfoKey(mkey)[1]
            for i in range(num_vals):
                name, val, _ = winreg.EnumValue(mkey, i)
                if name.startswith(r"\DosDevices\\") or name.startswith(r"\??\Volume"):
                    mounted.append({
                        "mount_point": name,
                        "raw_signature": str(val)[:30] if val else ""
                    })
    except Exception:
        pass

    return {
        "usbstor_devices": usb_devices,
        "mounted_devices": mounted
    }

def get_active_connections() -> list:
    """
    TR: netstat -ano komutunu çalıştırarak mevcut dinleyen veya kurulu TCP bağlantılarını ve PID'leri listeler.
    Captures active network sockets, state, and owning process IDs via netstat.
    """
    connections = []
    try:
        output = subprocess.check_output(["netstat", "-ano", "-p", "tcp"], text=True, stderr=subprocess.DEVNULL)
        lines = output.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("Active") or line.startswith("Proto"):
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP":
                connections.append({
                    "protocol": parts[0],
                    "local_address": parts[1],
                    "foreign_address": parts[2],
                    "state": parts[3],
                    "pid": int(parts[4]) if parts[4].isdigit() else parts[4]
                })
    except Exception:
        pass

    return connections[:150]

def collect_network_artifacts() -> dict:
    """
    TR: Ağ profilleri, USB geçmişi ve aktif soketleri bir araya getirir.
    Aggregates network history, USB drive records, and live sockets.
    """
    hostname = socket.gethostname()
    try:
        ip_addresses = socket.gethostbyname_ex(hostname)[2]
    except Exception:
        ip_addresses = []

    return {
        "hostname": hostname,
        "local_ips": ip_addresses,
        "wifi_profiles": get_wifi_and_network_profiles(),
        "usb_storage_history": get_usbstor_history(),
        "active_tcp_connections": get_active_connections()
    }
