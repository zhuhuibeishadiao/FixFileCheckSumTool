#include <stdio.h>

#include <stdio.h>
#include <Windows.h>
#include <IMAGEHLP.H>
#pragma comment(lib,"ImageHlp.lib")

#define  FIND(struc,e) (unsigned int)&(((struc *)0)->e)

void MyCls(HANDLE hConsole)
{
    COORD   coordScreen = { 0, 0 };//设置清屏后光标返回的屏幕左上角坐标
    BOOL	bSuccess;
    DWORD   cCharsWritten;
    CONSOLE_SCREEN_BUFFER_INFO   csbi;//保存缓冲区信息   
    DWORD   dwConSize;//当前缓冲区可容纳的字符数   
    bSuccess = GetConsoleScreenBufferInfo(hConsole, &csbi);//获得缓冲区信息   
    dwConSize = csbi.dwSize.X*csbi.dwSize.Y;//缓冲区容纳字符数目   
    bSuccess = FillConsoleOutputCharacter(hConsole, (TCHAR)' ', dwConSize, coordScreen, &cCharsWritten);
    bSuccess = GetConsoleScreenBufferInfo(hConsole, &csbi);//获得缓冲区信息   
    bSuccess = FillConsoleOutputAttribute(hConsole, csbi.wAttributes, dwConSize, coordScreen, &cCharsWritten);
    bSuccess = SetConsoleCursorPosition(hConsole, coordScreen);
    return;
}

void clrscr(void)
{
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    MyCls(hStdOut);
    return;
}

DWORD FileLen(char *filename)
{
    WIN32_FIND_DATAA fileInfo = { 0 };
    DWORD fileSize = 0;
    HANDLE hFind;
    hFind = FindFirstFileA(filename, &fileInfo);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        fileSize = fileInfo.nFileSizeLow;
        FindClose(hFind);
    }
    return fileSize;
}

CHAR *LoadFile(char *filename)
{
    DWORD dwReadWrite, LenOfFile = FileLen(filename);
    HANDLE hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        printf("文件大小:0x%llx\n", LenOfFile);
        PCHAR buffer = (PCHAR)malloc(LenOfFile);
        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        ReadFile(hFile, buffer, LenOfFile, &dwReadWrite, 0);
        CloseHandle(hFile);
        return buffer;
    }
    return NULL;
}

VOID ShowPE64Info(char *filename)
{
    PIMAGE_NT_HEADERS64 pinths64;
    PIMAGE_DOS_HEADER pdih;
    char *filedata;
    DWORD i = 0;
    DWORD HeaderSum, CheckSum;
    HANDLE hWriteFile;
    DWORD dwFileLen;
    DWORD dwWriteLen;
    DWORD dwCheckSumOffset = FIND(IMAGE_OPTIONAL_HEADER64, CheckSum);

    filedata = LoadFile(filename);
    //获得文件入口
    pdih = (PIMAGE_DOS_HEADER)filedata;
    //将文件入口转换为DOS头指针
    pinths64 = (PIMAGE_NT_HEADERS64)(filedata + pdih->e_lfanew);
    //获取NT头
    if (pinths64->Signature != 0x00004550)//PE00
    {
        printf("无效的PE文件！\n");
        return;
    }
    if (pinths64->OptionalHeader.Magic != 0x20b)//判断是不是PE+格式文件
    {
        printf("不是PE32+格式的文件！\n");
        return;
    }

    printf("\n");
    printf("入口点：          %llx\n", pinths64->OptionalHeader.AddressOfEntryPoint);
    printf("镜像基址：        %llx\n", pinths64->OptionalHeader.ImageBase);
    printf("镜像大小：        %llx\n", pinths64->OptionalHeader.SizeOfImage);
    printf("代码基址：        %llx\n", pinths64->OptionalHeader.BaseOfCode);
    printf("块对齐：          %llx\n", pinths64->OptionalHeader.SectionAlignment);
    printf("文件块对齐：      %llx\n", pinths64->OptionalHeader.FileAlignment);
    printf("子系统：          %llx\n", pinths64->OptionalHeader.Subsystem);
    printf("区段数目：        %llx\n", pinths64->FileHeader.NumberOfSections);
    printf("时间日期标志：    %llx\n", pinths64->FileHeader.TimeDateStamp);
    printf("首部大小：        %llx\n", pinths64->OptionalHeader.SizeOfHeaders);
    printf("特征值：          %llx\n", pinths64->FileHeader.Characteristics);
    printf("校验和：          %llx\n", pinths64->OptionalHeader.CheckSum);
    printf("可选头部大小：    %llx\n", pinths64->FileHeader.SizeOfOptionalHeader);
    printf("RVA 数及大小：    %llx\n", pinths64->OptionalHeader.NumberOfRvaAndSizes);

    printf("\n");
    dwFileLen = FileLen(filename);
    printf("PatchCheckSum do!\n");
    CheckSumMappedFile(filedata, dwFileLen, &HeaderSum, &CheckSum);
    printf("计算校验和：          %llx\n", CheckSum);
    printf("计算头部校验和：          %llx\n", HeaderSum);

    pinths64->OptionalHeader.CheckSum = CheckSum;

    printf("校验和：0x%x\n", pinths64->OptionalHeader.CheckSum);

    printf("WritrFile do!\n");

    hWriteFile = CreateFile(L"Patch.exe",
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hWriteFile == INVALID_HANDLE_VALUE)
    {
        printf("WriteFile Faild!\n");
        return;
    }

    if (!WriteFile(hWriteFile, filedata, dwFileLen, &dwWriteLen, NULL))
    {
        printf("WriteFile Faild!  Error code:0x%x\n", GetLastError());
    }

    printf("WriteFile Success!\n");
    CloseHandle(hWriteFile);
}

void PrintCUI()
{
    char filename[MAX_PATH] = { 0 };
    SetConsoleTitleA("FixSumToolx64");
bgn:
    printf("FixSumToolx64\n");
    printf("输入文件名（支持文件拖拽)输入exit退出）:");
    gets(filename);
    if (FileLen(filename) == 0)
    {
        if (stricmp(filename, "exit"))
        {
            printf("无效的文件\n");
            goto invail;
        }
        else
            goto end;
    }
    ShowPE64Info(filename);
invail:
    getchar();
    clrscr();
    goto bgn;
end:
    return;
}

int main(int argc, char* argv[])
{
    PrintCUI();
    return 0;
}