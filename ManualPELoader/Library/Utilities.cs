using ManualPELoader.Interop;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ManualPELoader.Library
{
    internal class Utilities
    {
        public static byte[] ConvertToShellcode(byte[] moduleBytes)
        {
            int nPeDataOffset;
            var bootcode64 = new byte[]
            {
                // _start:
                // Lệnh CALL +0: CPU sẽ đẩy địa chỉ lệnh kế tiếp (RIP hiện tại) vào stack
                0xE8, 0x00, 0x00, 0x00, 0x00,     

                // _prologue:
                // POP RCX: Lấy địa chỉ RIP từ stack và lưu vào RCX
                // RCX bây giờ chứa địa chỉ hiện tại (địa chỉ đoạn code đang chạy)
                0x59,
                
                // MOV R8D, <PE_DATA>
                0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, 

                // ADD RCX, R8 Tính địa chỉ tuyệt đối của PE_DATA
                0x4C, 0x01, 0xC1,                         
                // _loader:
                // <Loader ở đây>  
                // _pe_data:
                // Dữ liệu PE sẽ được chèn ở đây
            };

            var bootcode32 = new byte[]
            {
                // _start:
                // CALL +0  (5 bytes) -> push EIP vào stack
                0xE8, 0x00, 0x00, 0x00, 0x00,       

                // _prologue:
                // POP ECX: Lấy địa chỉ RIP từ stack và lưu vào RCX
                // ECX bây giờ chứa địa chỉ hiện tại (địa chỉ đoạn code đang chạy)
                0x59,
                
                // ADD ECX, <PE_DATA>
                // Thêm offset của PE data vào ECX để có được địa chỉ tuyệt đối của PE data
                0x81, 0xC1, 0x00, 0x00, 0x00, 0x00, 

                // PUSH EBP
                // Lưu giá trị cũ của EBP lên stack
                0x55,                              
                // MOV EBP, ESP
                // Thiết lập EBP cho khung ngăn xếp hiện tại, EBP = ESP
                0x89, 0xE5,    
                // PUSH ECX
                // Lưu địa chỉ PE data (ECX) lên stack để truyền tham số cho hàm loader
                0x51,   
                // CALL _loader
                // Loader sẽ thực thi việc tải PE từ địa chỉ trong ECX
                0xE8, 0x02, 0x00, 0x00, 0x00,   
                // leave
                // Dọn dẹp khung ngăn xếp hiện tại, ESP = EBP; pop EBP từ stack
                0xC9,   
                // RET
                // Lấy địa chỉ trả về từ stack và nhảy đến đó
                0xC3,                              
                // _loader:
                // <Loader ở đây>  
                // _pe_data:
                // Dữ liệu PE sẽ được chèn ở đây
            };

            var shellcode = new List<byte>();

            if(Helpers.GetPeArchitecture(moduleBytes) == IMAGE_FILE_MACHINE.AMD64) // Xác định kiến trúc file PE là 64bit
            {
                nPeDataOffset = bootcode64.Length + Resources.x64Loader.Length - 5; // Tính toán offset của đoạn mã để patch vào bootcode64
                Buffer.BlockCopy(BitConverter.GetBytes(nPeDataOffset), 0, bootcode64, 8, Marshal.SizeOf(typeof(int))); // Patch offset PE data vào bootcode64
                
                foreach (var b in bootcode64)
                {
                    shellcode.Add(b);
                }
                foreach (var b in Resources.x64Loader)
                {
                    shellcode.Add(b);
                }

            }
            else if(Helpers.GetPeArchitecture(moduleBytes) == IMAGE_FILE_MACHINE.I386)
            {
                nPeDataOffset = bootcode32.Length + Resources.x86Loader.Length - 5; // Tính toán offset của đoạn mã để patch vào bootcode32
                Buffer.BlockCopy(BitConverter.GetBytes(nPeDataOffset), 0, bootcode32, 8, Marshal.SizeOf(typeof(int))); // Patch offset PE data vào bootcode32
                
                foreach (var b in bootcode32)
                {
                    shellcode.Add(b);
                }
                foreach (var b in Resources.x86Loader)
                {
                    shellcode.Add(b);
                }
            }
            
            foreach (var b in moduleBytes)
            {
                shellcode.Add(b);
            }
            return shellcode.ToArray();

        }
    }
}
