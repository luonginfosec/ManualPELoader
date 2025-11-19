using System;
using ManualPELoader.Library;
namespace ManualPELoader
{
    internal class Program
    {
        public static int getPIDbyName(string processName)
        {
            var processes = System.Diagnostics.Process.GetProcessesByName(processName.Replace(".exe",""));
            if (processes.Length > 0)
            {
                return processes[0].Id;
            }
            else
            {
                return -1; 
            }
        }
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.ForegroundColor = System.ConsoleColor.Green;
            if (args.Length == 0)
            {
                args = new string[2] { "SimpleEXE.exe", "Notepad.exe" };
            }
            if (args.Length == 2)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    Console.WriteLine($"[+] Tham số truyền vào thứ {i}: {args[i]}");
                }
                byte[] moduleBytes = [];
                Console.WriteLine($"[+] Tiến hành load {args[0]} vào {args[1]}");
                try
                {
                    moduleBytes = File.ReadAllBytes(args[0]);
                    Console.WriteLine($"[+] {moduleBytes.Length} bytes đã đọc thành công!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Lỗi khi đọc file: " + ex.Message);
                    return;
                }
                int pid = getPIDbyName(args[1]);
                if (pid == -1)
                {
                    Console.WriteLine("[-] Không tìm thấy tiến trình mục tiêu!");
                    return;
                }
                Console.WriteLine($"[+] Tìm thấy tiến trình mục tiêu với PID: {pid}");
                Modules.InjectShellcode(pid, moduleBytes);
            }
            else
            {
                Console.WriteLine("Vui lòng nhập đủ 2 tham số");
            }
            Console.ReadKey(); 
        }
    }
}