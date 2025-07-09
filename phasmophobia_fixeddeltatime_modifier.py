#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phasmophobia FixedDeltaTime 修改器
通过AOB搜索定位函数，动态解析指针链，修改fixedDeltaTime值实现游戏加速
作者：AI Assistant
"""

# ========== 配置参数 ==========
DEFAULT_FPS = 500                # 默认刷新率
MIN_FPS = 29                      # 最小允许刷新率
MAX_FPS = 1000                   # 最大允许刷新率
# ===============================

import ctypes
from ctypes import wintypes
import struct
import time
import sys

# Windows API 常量
PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008

# Windows API 结构体
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.CHAR * 260),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(wintypes.BYTE)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.CHAR * 256),
        ("szExePath", wintypes.CHAR * 260),
    ]

class PhasmophobiaModifier:
    def __init__(self):
        self.process_handle = None
        self.process_id = None
        self.unityplayer_base = None
        self.unityplayer_size = None
        
        # AOB 特征码：48 8B 05 ?? ?? ?? ?? F3 0F 10 40 48 C3
        self.aob_pattern = [
            0x48, 0x8B, 0x05, None, None, None, None,  # mov rax,[rip+offset]
            0xF3, 0x0F, 0x10, 0x40, 0x48,             # movss xmm0,[rax+48]
            0xC3                                       # ret
        ]
        
        self.current_fps = DEFAULT_FPS
        self.last_applied_fps = DEFAULT_FPS  # 记忆上一次应用的刷新率
        self.saved_aob_address = None  # 保存找到的AOB指令地址
        
    def find_process(self, process_name):
        """查找进程ID"""
        print(f"正在搜索进程: {process_name}")
        
        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == -1:
            return False
            
        process_entry = PROCESSENTRY32()
        process_entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        
        if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(process_entry)):
            while True:
                if process_entry.szExeFile.decode('utf-8', errors='ignore').lower() == process_name.lower():
                    self.process_id = process_entry.th32ProcessID
                    print(f"找到进程: {process_name} (PID: {self.process_id})")
                    ctypes.windll.kernel32.CloseHandle(snapshot)
                    return True
                    
                if not ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(process_entry)):
                    break
                    
        ctypes.windll.kernel32.CloseHandle(snapshot)
        return False
        
    def get_module_info(self, module_name):
        """获取模块基址和大小"""
        print(f"正在获取模块信息: {module_name}")
        
        snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.process_id)
        if snapshot == -1:
            return False
            
        module_entry = MODULEENTRY32()
        module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        
        if ctypes.windll.kernel32.Module32First(snapshot, ctypes.byref(module_entry)):
            while True:
                module_name_decoded = module_entry.szModule.decode('utf-8', errors='ignore')
                if module_name_decoded.lower() == module_name.lower():
                    self.unityplayer_base = ctypes.cast(module_entry.modBaseAddr, ctypes.c_void_p).value
                    self.unityplayer_size = module_entry.modBaseSize
                    print(f"找到模块: {module_name}")
                    ctypes.windll.kernel32.CloseHandle(snapshot)
                    return True
                    
                if not ctypes.windll.kernel32.Module32Next(snapshot, ctypes.byref(module_entry)):
                    break
                    
        ctypes.windll.kernel32.CloseHandle(snapshot)
        return False
        
    def open_process(self):
        """打开进程句柄"""
        self.process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.process_id)
        return self.process_handle is not None
        
    def read_memory(self, address, size):
        """读取内存"""
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            success = ctypes.windll.kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            return buffer.raw if success and bytes_read.value == size else None
        except:
            return None
        
    def write_memory(self, address, data):
        """写入内存"""
        try:
            bytes_written = ctypes.c_size_t()
            buffer = ctypes.create_string_buffer(data)
            
            success = ctypes.windll.kernel32.WriteProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                buffer,
                len(data),
                ctypes.byref(bytes_written)
            )
            
            return success and bytes_written.value == len(data)
        except:
            return False
            

        
    def is_valid_deltatime_value(self, value):
        """验证deltatime值是否在允许范围内（统一使用配置参数）"""
        min_deltatime = 1.0 / MAX_FPS
        max_deltatime = 1.0 / MIN_FPS
        return min_deltatime <= value <= max_deltatime
        
    def verify_address(self, instruction_address):
        """验证指令地址是否指向有效的fixedDeltaTime"""
        try:
            # 1. 解析 mov rax,[rip+offset] 指令
            offset_data = self.read_memory(instruction_address + 3, 4)
            if not offset_data:
                return None
                
            offset = struct.unpack('<i', offset_data)[0]
            global_pointer_address = instruction_address + 7 + offset
            
            # 2. 读取全局指针内容
            pointer_data = self.read_memory(global_pointer_address, 8)
            if not pointer_data:
                return None
                
            pointer_value = struct.unpack('<Q', pointer_data)[0]
            if pointer_value == 0:
                return None
                
            # 3. 计算最终数据地址
            data_address = pointer_value + 0x48
            
            # 4. 验证数据值
            data = self.read_memory(data_address, 4)
            if not data:
                return None
                
            value = struct.unpack('<f', data)[0]
            
            # 验证值是否在合理范围内（统一使用配置参数）
            if self.is_valid_deltatime_value(value):
                print(f"当前值: {value} (对应 {1.0/value:.1f} FPS)")
                return data_address
                
        except:
            pass
            
        return None
        
    def modify_deltatime(self, data_address, fps):
        """修改fixedDeltaTime值"""
        deltatime = 1.0 / fps
        data_bytes = struct.pack('<f', deltatime)
        
        if self.write_memory(data_address, data_bytes):
            # 验证修改结果
            verification_data = self.read_memory(data_address, 4)
            if verification_data:
                verification_value = struct.unpack('<f', verification_data)[0]
                return abs(verification_value - deltatime) < 0.000001
        return False

    def close_process_handle(self):
        """关闭进程句柄"""
        if self.process_handle:
            ctypes.windll.kernel32.CloseHandle(self.process_handle)
            self.process_handle = None
            
    def initialize_process_and_module(self):
        """初始化进程和模块，返回是否成功"""
        # 关闭之前的句柄
        self.close_process_handle()
        
        # 查找进程
        if not self.find_process("Phasmophobia.exe"):
            print("✗ 未找到Phasmophobia.exe进程，请确保游戏正在运行")
            return False
            
        # 打开进程
        if not self.open_process():
            print("✗ 打开进程失败，可能需要管理员权限")
            return False
            
        # 获取模块信息
        if not self.get_module_info("UnityPlayer.dll"):
            print("✗ 获取UnityPlayer.dll模块信息失败")
            return False
            
        print("✓ 成功连接到游戏进程")
        return True
        
    def get_data_address_from_aob(self, aob_address):
        """从AOB指令地址解析出数据地址"""
        try:
            # 1. 解析 mov rax,[rip+offset] 指令
            offset_data = self.read_memory(aob_address + 3, 4)
            if not offset_data:
                return None
                
            offset = struct.unpack('<i', offset_data)[0]
            global_pointer_address = aob_address + 7 + offset
            
            # 2. 读取全局指针内容
            pointer_data = self.read_memory(global_pointer_address, 8)
            if not pointer_data:
                return None
                
            pointer_value = struct.unpack('<Q', pointer_data)[0]
            if pointer_value == 0:
                return None
                
            # 3. 计算最终数据地址
            data_address = pointer_value + 0x48
            return data_address
            
        except:
            return None

    def validate_and_clean_input(self, user_input):
        """验证和清洗用户输入"""
        # 去除首尾空白字符
        cleaned_input = user_input.strip()
            
        # 检查输入是否为空 - 如果为空则使用记忆的刷新率
        if not cleaned_input:
            return 'use_last_applied', self.last_applied_fps
            
        # 检查输入格式：ASCII数字，长度1-4位
        if not (cleaned_input.isascii() and cleaned_input.isdigit() and 1 <= len(cleaned_input) <= 4):
            return 'invalid_format', None
            
        try:
            # 转换为浮点数
            fps_value = float(cleaned_input)
            
            # 检查数值范围
            if fps_value <= 0:
                return 'invalid_range', "刷新率必须大于0"
            elif fps_value > MAX_FPS:
                return 'invalid_range', f"刷新率过高，不能超过{MAX_FPS}Hz"
            elif fps_value < MIN_FPS:
                return 'invalid_range', f"刷新率过低，不能小于{MIN_FPS}Hz"
                
            return 'valid', fps_value
            
        except ValueError:
            return 'invalid_number', None

    def run(self):
        """主执行函数"""
        print("=== Phasmophobia FixedDeltaTime 修改器 ===")
        print("正在初始化，检测游戏进程...")
        print()
        
        try:
            # 首次启动时执行一遍完整流程
            if self.initialize_process_and_module():
                print("正在搜索AOB地址...")
                aob_address = self.search_aob_only()
                if aob_address:
                    data_address = self.verify_address(aob_address)
                    if data_address:
                        self.saved_aob_address = aob_address  # 保存AOB指令地址
                        print(f"✓ 找到并保存AOB地址: 0x{aob_address:X}")
                        
                        # 读取并显示当前值
                        data = self.read_memory(data_address, 4)
                        if data:
                            current_value = struct.unpack('<f', data)[0]
                            current_fps = 1.0 / current_value
                            print(f"✓ 当前刷新率: {current_fps:.1f} Hz (deltaTime: {current_value:.6f})")
                            
                            # 程序启动时自动应用记忆的刷新率
                            print(f"正在自动应用记忆的刷新率: {self.last_applied_fps} Hz...")
                            if self.modify_deltatime(data_address, self.last_applied_fps):
                                print(f"✓ 成功自动设置刷新率: {self.last_applied_fps} Hz")
                            else:
                                print("✗ 自动设置失败")
                        else:
                            print("✗ 无法读取当前值")
                    else:
                        print("✗ AOB地址验证失败")
                else:
                    print("✗ 未找到AOB地址")
            else:
                print("⚠ 初始化失败，但程序将继续运行")
                print("请确保游戏正在运行，然后输入数值进行设置")
                
            print()
            print("=== 交互式刷新率修改 ===")
            print(f"输入新的刷新率来修改游戏速度 (直接按回车使用记忆值: {self.last_applied_fps} Hz)")
            print()
            while True:
                try:
                    user_input = input("请输入刷新率: ")
                    
                    # 验证和清洗输入
                    status, value = self.validate_and_clean_input(user_input)
                    
                    if status == 'use_last_applied':
                        new_fps = value
                        print(f"\n使用记忆的刷新率: {new_fps} Hz...")
                    elif status == 'invalid_format':
                        print("✗ 输入格式无效，请输入1-4位数字")
                        continue
                    elif status == 'invalid_range':
                        print(f"✗ {value}")
                        continue
                    elif status == 'invalid_number':
                        print("✗ 输入无效，请输入数字")
                        continue
                    elif status == 'valid':
                        new_fps = value
                        # 用户输入了有效数值，开始处理
                        print(f"\n正在处理刷新率设置: {new_fps} Hz...")
                    else:
                        print("✗ 未知错误")
                        continue
                    
                    # 初始化进程和模块
                    if not self.initialize_process_and_module():
                        continue
                        
                    data_address = None
                    
                    # 如果已经保存了AOB地址，直接使用
                    if self.saved_aob_address:
                        print("使用已保存的AOB地址...")
                        data_address = self.get_data_address_from_aob(self.saved_aob_address)
                        if data_address:
                            # 验证数据是否有效（统一使用配置参数）
                            data = self.read_memory(data_address, 4)
                            if data:
                                value = struct.unpack('<f', data)[0]
                                if not self.is_valid_deltatime_value(value):
                                    print("✗ 保存的AOB地址无效，重新搜索...")
                                    data_address = None
                                    self.saved_aob_address = None
                            else:
                                print("✗ 无法读取数据，重新搜索...")
                                data_address = None
                                self.saved_aob_address = None
                    
                    # 如果没有保存的AOB地址或验证失败，重新搜索
                    if not data_address:
                        print("正在搜索AOB地址...")
                        aob_address = self.search_aob_only()
                        if aob_address:
                            data_address = self.verify_address(aob_address)
                            if data_address:
                                self.saved_aob_address = aob_address  # 保存AOB指令地址
                                print(f"✓ 找到并保存AOB地址: 0x{aob_address:X}")
                            else:
                                print("✗ AOB地址验证失败")
                        else:
                            print("✗ 未找到AOB地址")
                            
                    # 如果找到了有效的数据地址，执行修改
                    if data_address:
                        if self.modify_deltatime(data_address, new_fps):
                            self.current_fps = new_fps
                            self.last_applied_fps = new_fps  # 更新记忆的刷新率
                            print(f"✓ 成功设置刷新率: {new_fps} Hz")
                        else:
                            print("✗ 设置失败")
                    else:
                        print("✗ 无法找到有效的内存地址")
                        
                    print()  # 空行分隔
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"✗ 处理输入时发生错误: {e}")
                    continue
                    
            return True
            
        except Exception as e:
            print(f"发生错误: {e}")
            return False
            
        finally:
            self.close_process_handle()
            
    def search_aob_only(self):
        """只搜索AOB，返回指令地址"""
        if not self.unityplayer_base or not self.unityplayer_size:
            return None
            
        # 读取整个模块
        module_data = self.read_memory(self.unityplayer_base, self.unityplayer_size)
        if not module_data:
            return None
            
        # 搜索模式匹配
        pattern_len = len(self.aob_pattern)
        data_len = len(module_data)
        
        for i in range(data_len - pattern_len + 1):
            # 检查模式匹配
            match = True
            for j in range(pattern_len):
                if self.aob_pattern[j] is not None and module_data[i + j] != self.aob_pattern[j]:
                    match = False
                    break
                    
            if match:
                # 找到匹配，返回指令地址
                instruction_address = self.unityplayer_base + i
                return instruction_address
                
        return None

def main():
    """主入口函数"""
    modifier = PhasmophobiaModifier()
    success = modifier.run()
    
    if not success:
        print("修改失败，请检查游戏是否运行")
        sys.exit(1)

if __name__ == "__main__":
    main() 