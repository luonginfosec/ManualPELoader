using ManualPELoader.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ManualPELoader.Library
{
    internal class Helpers
    {
        public static bool IsValidPe(byte[] moduleBytes)
        {
            IntPtr pModule; 
            var status = false;
            if (moduleBytes.Length > 0x400)
            {
                pModule = Marshal.AllocHGlobal(0x400);
                Marshal.Copy(moduleBytes, 0, pModule, 0x400);

                status = IsValidPe(pModule);

                Marshal.FreeHGlobal(pModule);
            }
            return status;
        }
        public static bool IsValidPe(IntPtr pModule)
        {
            int e_lfanew;
            bool status = false;
            if (Marshal.ReadInt16(pModule) != 0x5A4D) // Kiểm tra chữ ký "MZ"
                return false;
            e_lfanew = Marshal.ReadInt32(pModule, 0x3C); // Đọc e_lfanew từ cấu trúc DOS Header
            if (e_lfanew > 0x400)
            {
                return false;
            }
            if (Marshal.ReadInt32(pModule, e_lfanew) != 0x00004550) // Kiểm tra chữ ký "PE\0\0"
                return false;
            status = true;
            return status;
        }
        public static IMAGE_FILE_MACHINE GetPeArchitecture(byte[] moduleBytes)
        {
            // Địa chỉ tạm thời để lưu trữ phần đầu của module
            IntPtr pModuleBase;
            IMAGE_FILE_MACHINE machine = 0;

            if (moduleBytes.Length > 0x400)
            {
                // Cấp phát bộ nhớ không quản lý để lưu trữ phần đầu của module
                pModuleBase = Marshal.AllocHGlobal(0x400);
                // Sao chép phần đầu của module vào bộ nhớ không quản lý
                Marshal.Copy(moduleBytes, 0, pModuleBase, 0x400);
                // Lấy kiến trúc PE từ bộ nhớ không quản lý
                machine = GetPeArchitecture(pModuleBase);
                // Giải phóng bộ nhớ không quản lý
                Marshal.FreeHGlobal(pModuleBase);
            }
            return machine;
        }
        public static IMAGE_FILE_MACHINE GetPeArchitecture(IntPtr pModuleBase)
        {
            int e_lfanew;
            IMAGE_FILE_MACHINE machine = 0;
            // Kiểm tra chữ ký "MZ"
            // Đọc 2 byte đầu tiên từ địa chỉ pModuleBase
            if (Marshal.ReadInt16(pModuleBase) != 0x5A4D)
                return 0;
            // Đọc e_lfanew từ cấu trúc DOS Header để tìm vị trí của NT Headers hay PE Header
            // Đọc 4 byte tại offset 0x3C
            e_lfanew = Marshal.ReadInt32(pModuleBase, 0x3C);
            // Giới hạn e_lfanew để tránh đọc ngoài phạm vi hợp lệ
            if (e_lfanew > 0x800)
                return 0;
            // Kiểm tra chữ ký "PE\0\0" 
            if (Marshal.ReadInt32(pModuleBase, e_lfanew) != 0x00004550)
                return 0;
            // Đọc trường Machine từ cấu trúc File Header
            machine = (IMAGE_FILE_MACHINE)Marshal.ReadInt16(pModuleBase, e_lfanew + 4);
            return machine;
        }
    }
}
