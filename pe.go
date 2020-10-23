package pefile

type ImageBaseRelocation struct {
	VirtualAddress, SizeOfBlock uint32
}

const ImageBaseRelocationSize = 8

const (
	IMAGE_REL_BASED_ABSOLUTE       = 0
	IMAGE_REL_BASED_HIGH           = 1
	IMAGE_REL_BASED_LOW            = 2
	IMAGE_REL_BASED_HIGHLOW        = 3
	IMAGE_REL_BASED_HIGHADJ        = 4
	IMAGE_REL_BASED_MIPS_JMPADDR   = 5
	IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
	IMAGE_REL_BASED_IA64_IMM64     = 9
	IMAGE_REL_BASED_DIR64          = 10
)

type ImageDataDirectory struct {
	VirtualAddress, Size uint32
}

//OptionHeader.Magic
const (
	ImageOptionHeaderMagicHdr32 = 0x10b
	ImageOptionHeaderMagicHdr64 = 0x20b
	ImageOptionHeaderMagicRom   = 0x107
)

//SectionHeader.Characteristics
const (
	IMAGE_SCN_TYPE_NO_PAD            = 0x00000008
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_LNK_OTHER              = 0x00000100
	IMAGE_SCN_LNK_INFO               = 0x00000200
	IMAGE_SCN_LNK_REMOVE             = 0x00000800
	IMAGE_SCN_LNK_COMDAT             = 0x00001000
	IMAGE_SCN_NO_DEFER_SPEC_EXC      = 0x00004000
	IMAGE_SCN_GPREL                  = 0x00008000
	IMAGE_SCN_MEM_FARDATA            = 0x00008000
	IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
	IMAGE_SCN_MEM_16BIT              = 0x00020000
	IMAGE_SCN_MEM_LOCKED             = 0x00040000
	IMAGE_SCN_MEM_PRELOAD            = 0x00080000
	IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
	IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
	IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
	IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
	IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
	IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
	IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
	IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000
	IMAGE_SCN_ALIGN_MASK             = 0x00F00000
	IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)

//FileHeader.Characteristics
const (
	IMAGE_FILE_RELOCS_STRIPPED         = 0x0001
	IMAGE_FILE_EXECUTABLE_IMAGE        = 0x0002
	IMAGE_FILE_LINE_NUMS_STRIPPED      = 0x0004
	IMAGE_FILE_LOCAL_SYMS_STRIPPED     = 0x0008
	IMAGE_FILE_AGGRESIVE_WS_TRIM       = 0x0010
	IMAGE_FILE_LARGE_ADDRESS_AWARE     = 0x0020
	IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080
	IMAGE_FILE_32BIT_MACHINE           = 0x0100
	IMAGE_FILE_DEBUG_STRIPPED          = 0x0200
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400
	IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800
	IMAGE_FILE_SYSTEM                  = 0x1000
	IMAGE_FILE_DLL                     = 0x2000
	IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000
	IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000
)

//OptionHeader.Subsytem
const (
	IMAGE_SUBSYSTEM_UNKNOWN                  = 0
	IMAGE_SUBSYSTEM_NATIVE                   = 1
	IMAGE_SUBSYSTEM_WINDOWS_GUI              = 2
	IMAGE_SUBSYSTEM_WINDOWS_CUI              = 3
	IMAGE_SUBSYSTEM_OS2_CUI                  = 5
	IMAGE_SUBSYSTEM_POSIX_CUI                = 7
	IMAGE_SUBSYSTEM_NATIVE_WINDOWS           = 8
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI           = 9
	IMAGE_SUBSYSTEM_EFI_APPLICATION          = 10
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER  = 11
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER       = 12
	IMAGE_SUBSYSTEM_EFI_ROM                  = 13
	IMAGE_SUBSYSTEM_XBOX                     = 14
	IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
)

//Option.DllCharacteristics
const (
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE          = 0x0040
	IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY       = 0x0080
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT             = 0x0100
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION          = 0x0200
	IMAGE_DLLCHARACTERISTICS_NO_SEH                = 0x0400
	IMAGE_DLLCHARACTERISTICS_NO_BIND               = 0x0800
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER            = 0x2000
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
)

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

var peHeader = peHeaderB8

var peHeader80 = []byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
	0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
	0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
	0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x45, 0x00, 0x00,
}

var peHeaderB8 = []byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00,
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
	0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
	0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
	0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xF9, 0x2D, 0x54, 0xD9, 0xBD, 0x4C, 0x3A, 0x8A,
	0xBD, 0x4C, 0x3A, 0x8A, 0xBD, 0x4C, 0x3A, 0x8A,
	0x9A, 0x8A, 0x46, 0x8A, 0xBC, 0x4C, 0x3A, 0x8A,
	0xBD, 0x4C, 0x3A, 0x8A, 0xB1, 0x4C, 0x3A, 0x8A,
	0x9A, 0x8A, 0x42, 0x8A, 0xBC, 0x4C, 0x3A, 0x8A,
	0x52, 0x69, 0x63, 0x68, 0xBD, 0x4C, 0x3A, 0x8A,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x45, 0x00, 0x00,
}

var peHeader100 = []byte{
	0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
	0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
	0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
	0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
	0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
	0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
	0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
	0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xA5, 0x0A, 0xE4, 0x21, 0xE1, 0x6B, 0x8A, 0x72,
	0xE1, 0x6B, 0x8A, 0x72, 0xE1, 0x6B, 0x8A, 0x72,
	0x8E, 0x0F, 0x89, 0x73, 0xEB, 0x6B, 0x8A, 0x72,
	0x8E, 0x0F, 0x8F, 0x73, 0x6E, 0x6B, 0x8A, 0x72,
	0x8E, 0x0F, 0x8E, 0x73, 0xF3, 0x6B, 0x8A, 0x72,
	0x8E, 0x0F, 0x8B, 0x73, 0xE2, 0x6B, 0x8A, 0x72,
	0xE1, 0x6B, 0x8B, 0x72, 0xAC, 0x6B, 0x8A, 0x72,
	0xF2, 0x0D, 0x89, 0x73, 0xF3, 0x6B, 0x8A, 0x72,
	0xF2, 0x0D, 0x8F, 0x73, 0xC2, 0x6B, 0x8A, 0x72,
	0xF2, 0x0D, 0x8E, 0x73, 0xF0, 0x6B, 0x8A, 0x72,
	0xA0, 0x0C, 0x8E, 0x73, 0xE0, 0x6B, 0x8A, 0x72,
	0xA0, 0x0C, 0x88, 0x73, 0xE0, 0x6B, 0x8A, 0x72,
	0x52, 0x69, 0x63, 0x68, 0xE1, 0x6B, 0x8A, 0x72,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x50, 0x45, 0x00, 0x00,
}
