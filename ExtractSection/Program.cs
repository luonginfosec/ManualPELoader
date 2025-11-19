using System;
namespace ExtractSection
{
    internal class Program
    {
        static void ExtractPESection(byte[] moduleBytes, string nameFile)
        {
            int peHeaderOffset = BitConverter.ToInt32(moduleBytes, 0x3C); // Lấy offset của PE header từ vị trí 0x3C
            Console.WriteLine($"[+] PE Header Offset: 0x{peHeaderOffset:X}"); 
            int sectionCount = BitConverter.ToInt16(moduleBytes, peHeaderOffset + 6); // Lấy số section từ PE header
            Console.WriteLine($"[+] Số section: 0x{sectionCount:X}");
            int optionalHeaderSize = BitConverter.ToInt16(moduleBytes, peHeaderOffset + 20); // Lấy kích thước Optional Header
            Console.WriteLine($"[+] Kích thước Optional Header: 0x{optionalHeaderSize:X}");
            int sectionTableOffset = peHeaderOffset + 4 + 20 + optionalHeaderSize;  // Tính offset của Section Table
            Console.WriteLine($"[+] Section Table Offset: 0x{sectionTableOffset:X}");
            Console.WriteLine("[+] Danh sách các section:");
            for(int i = 0; i < sectionCount; i++)
            {
                int sectionOffset = sectionTableOffset + (i * 40);  // Mỗi section header có kích thước 40 bytes
                string sectionName = System.Text.Encoding.UTF8.GetString(moduleBytes, sectionOffset, 8); // Tên section dài 8 bytes
                Console.WriteLine($"[*] Section {i + 1}: {sectionName}");
            }
            Console.WriteLine("[+] Vui lòng nhập số section cần trích xuất");
            int sectionIndex = -1;
            while (sectionIndex < 0 || sectionIndex >= sectionCount)
            {
                Console.Write("[+] Nhập số section cần trích xuất: ");
                string? input = Console.ReadLine();
                if (input == null)
                {
                    Console.WriteLine("[-] Vui lòng nhập số hợp lệ!");
                    continue;
                }
                if (!int.TryParse(input, out sectionIndex) || sectionIndex < 1 || sectionIndex > sectionCount)
                {
                    Console.WriteLine("[-] Vui lòng nhập số hợp lệ!");
                    sectionIndex = -1;
                }
                else
                {
                    sectionIndex -= 1; 
                }
            }
            // Lấy thông tin section đã chọn
            int chosenSectionOffset = sectionTableOffset + (sectionIndex * 40);
            string selectedSectionName = System.Text.Encoding.UTF8.GetString(moduleBytes, chosenSectionOffset, 8);
            Console.WriteLine($"[+] Bạn đã chọn section: {selectedSectionName}");
            int virtualSize = BitConverter.ToInt32(moduleBytes, chosenSectionOffset + 8);
            int virtualAddress = BitConverter.ToInt32(moduleBytes, chosenSectionOffset + 12);
            int sizeOfRawData = BitConverter.ToInt32(moduleBytes, chosenSectionOffset + 16);
            int pointerToRawData = BitConverter.ToInt32(moduleBytes, chosenSectionOffset + 20);
            Console.WriteLine($"[+] Virtual Size: 0x{virtualSize:X}");
            Console.WriteLine($"[+] Virtual Address: 0x{virtualAddress:X}");
            Console.WriteLine($"[+] Size of Raw Data: 0x{sizeOfRawData:X}");
            Console.WriteLine($"[+] Pointer to Raw Data: 0x{pointerToRawData:X}");
            byte[] sectionData = new byte[sizeOfRawData];
            Array.Copy(moduleBytes, pointerToRawData, sectionData, 0, sizeOfRawData);
            string outputFileName = nameFile + ".bin";
            try
            {
                File.WriteAllBytes(outputFileName, sectionData);
                Console.WriteLine($"[+] Section đã được trích xuất thành công vào file: {outputFileName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Lỗi khi ghi file: " + ex.Message);
            }
            string text = "byte[] data = {";
            for (int i = 0; i < sectionData.Length; i++)
            {
                if (i % 12 == 0)
                {
                    text += "\n    ";
                }
                text += "0x" + sectionData[i].ToString("X2");
                if (i != sectionData.Length - 1)
                {
                    text += ", ";
                }
            }
            text += "\n};";
            string outputCodeFileName = nameFile + "Array.txt";
            try
            {
                File.WriteAllText(outputCodeFileName, text);
                Console.WriteLine($"[+] Mã nguồn của section đã được ghi vào file: {outputCodeFileName}");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Lỗi khi ghi file mã nguồn: " + ex.Message);
            }
        }
        static void Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.ForegroundColor = System.ConsoleColor.Green;
            string path = Environment.CurrentDirectory;
            string[] listFile = System.IO.Directory.GetFiles(path, "*.exe", System.IO.SearchOption.AllDirectories);
            for (int i = 0; i < listFile.Length; i++)
            {
                string fileName = Path.GetFileName(listFile[i]);
                Console.WriteLine($"[+] {i + 1}: {fileName}");
            }
            int fileIndex = -1;
            while (fileIndex < 0 || fileIndex >= listFile.Length)
            {
                Console.Write("[+] Nhập số file cần trích xuất: ");
                string? input = Console.ReadLine();
                if (input == null)
                {
                    Console.WriteLine("[-] Vui lòng nhập số hợp lệ!");
                    continue;
                }
                if (!int.TryParse(input, out fileIndex) || fileIndex < 1 || fileIndex > listFile.Length)
                {
                    Console.WriteLine("[-] Vui lòng nhập số hợp lệ!");
                    fileIndex = -1;
                }
                else
                {
                    fileIndex -= 1; 
                }
            }
            Console.WriteLine($"[+] Bạn đã chọn: {Path.GetFileName(listFile[fileIndex])}");
            byte[] moduleBytes;
            try
            {
                moduleBytes = File.ReadAllBytes(listFile[fileIndex]);
                Console.WriteLine($"[+] {moduleBytes.Length} bytes đã đọc thành công!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Lỗi khi đọc file: " + ex.Message);
                return;
            }
            ExtractPESection(moduleBytes , listFile[fileIndex]);
            Console.WriteLine("Nhấn phím bất kỳ để thoát...");
            Console.ReadKey();
        }
    }
}