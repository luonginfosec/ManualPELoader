# ManualPELoader

Một dự án C# để tải thủ công các file PE (Portable Executable) vào tiến trình đích thông qua kỹ thuật process injection và trích xuất các section từ file PE.

## 📋 Mô tả

ManualPELoader bao gồm hai công cụ chính:

1. **ManualPELoader**: Tiêm shellcode được chuyển đổi từ file PE vào tiến trình đích
2. **ExtractSection**: Trích xuất các section cụ thể từ file PE và xuất thành mảng byte

## 🏗️ Kiến trúc dự án

```
ManualPELoader/
├── ManualPELoader/           # Project chính - PE injection tool
│   ├── Interop/             # Windows API declarations
│   │   ├── NativeMethods.cs
│   │   ├── Win32Consts.cs
│   │   └── Win32Enums.cs
│   ├── Library/             # Core functionality
│   │   ├── Helpers.cs       # PE validation và utilities
│   │   ├── Modules.cs       # Process injection logic
│   │   ├── Resources.cs     # Embedded loader shellcode
│   │   └── Utilities.cs     # PE to shellcode conversion
│   └── Program.cs           # Entry point
├── ExtractSection/          # PE section extraction tool
│   └── Program.cs
└── README.md
```

## ⚙️ Yêu cầu hệ thống

- **.NET 8.0** hoặc cao hơn
- **Windows** (sử dụng Windows APIs)
- Quyền **Administrator** (để truy cập vào các tiến trình khác)

## 🚀 Cách sử dụng

### ManualPELoader

Tiêm một file PE vào tiến trình đích:

```bash
ManualPELoader.exe <PE_file> <target_process>
```

**Ví dụ:**
```bash
ManualPELoader.exe SimpleEXE.exe Notepad.exe
```

**Tham số:**
- `PE_file`: Đường dẫn đến file PE cần tiêm
- `target_process`: Tên tiến trình đích (có thể bao gồm .exe)

### ExtractSection

Trích xuất section từ file PE:

```bash
ExtractSection.exe
```

Chương trình sẽ:
1. Liệt kê tất cả file .exe trong thư mục hiện tại
2. Cho phép chọn file PE
3. Hiển thị danh sách các section
4. Cho phép chọn section cần trích xuất
5. Xuất section thành file .bin và mảng byte C#

## 🔧 Tính năng

### ManualPELoader
- ✅ Hỗ trợ cả kiến trúc 32-bit và 64-bit
- ✅ Xác thực tính hợp lệ của file PE
- ✅ Kiểm tra tương thích kiến trúc
- ✅ Process injection với shellcode tùy chỉnh
- ✅ Sử dụng Windows NT APIs cho hiệu suất tối ưu

### ExtractSection
- ✅ Parse PE header và section table
- ✅ Liệt kê tất cả các section trong file PE
- ✅ Trích xuất section thành file binary
- ✅ Tạo mảng byte C# từ section data

## 🛠️ Build dự án

```bash
# Clone repository
git clone https://github.com/luonginfosec/ManualPELoader.git
cd ManualPELoader

# Build ManualPELoader
cd ManualPELoader
dotnet build --configuration Release

# Build ExtractSection
cd ../ExtractSection
dotnet build --configuration Release
```

## 🔒 Lưu ý bảo mật

⚠️ **CẢNH BÁO**: Công cụ này được thiết kế cho mục đích nghiên cứu bảo mật và giáo dục.

- Chỉ sử dụng trên hệ thống bạn sở hữu hoặc có quyền kiểm tra
- Không sử dụng cho mục đích bất hợp pháp
- Có thể bị phần mềm antivirus phát hiện như malware
- Yêu cầu quyền Administrator để hoạt động

## 📚 Kiến thức kỹ thuật

### PE Structure
- DOS Header và PE Header parsing
- Section Table analysis
- Architecture detection (x86/x64)

### Process Injection
- VirtualAllocEx - Memory allocation
- NtWriteVirtualMemory - Memory writing
- NtProtectVirtualMemory - Memory protection
- NtCreateThreadEx - Thread creation

### Shellcode Generation
- Custom bootloader cho x86 và x64
- Position-independent code
- PE manual loading

## 👨‍💻 Tác giả

- **luonginfosec** - [GitHub Profile](https://github.com/luonginfosec)

