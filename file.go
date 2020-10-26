package pefile

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"github.com/mtlicz/container"
	"io"
)

type PeFile struct {
	File                            *pe.File
	mySections                      []customSection
	va                              *container.Scope
	sectionAlignment, fileAlignment uint32
}

type OptionalHeader struct {
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               []pe.DataDirectory
}

func (p *PeFile) OptionHeader() *OptionalHeader {
	var ret OptionalHeader

	if p.File.OptionalHeader != nil {
		switch p.File.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			h := p.File.OptionalHeader.(*pe.OptionalHeader32)
			ret.MajorLinkerVersion = h.MajorLinkerVersion
			ret.MinorLinkerVersion = h.MinorLinkerVersion
			ret.SizeOfCode = h.SizeOfCode
			ret.SizeOfInitializedData = h.SizeOfInitializedData
			ret.SizeOfUninitializedData = h.SizeOfUninitializedData
			ret.AddressOfEntryPoint = h.AddressOfEntryPoint
			ret.BaseOfCode = h.BaseOfCode
			ret.ImageBase = uint64(h.ImageBase)
			ret.SectionAlignment = h.SectionAlignment
			ret.FileAlignment = h.FileAlignment
			ret.MajorOperatingSystemVersion = h.MajorOperatingSystemVersion
			ret.MinorOperatingSystemVersion = h.MinorOperatingSystemVersion
			ret.MajorImageVersion = h.MajorImageVersion
			ret.MinorImageVersion = h.MinorImageVersion
			ret.MajorSubsystemVersion = h.MajorSubsystemVersion
			ret.MinorSubsystemVersion = h.MinorSubsystemVersion
			ret.Win32VersionValue = h.Win32VersionValue
			ret.SizeOfImage = h.SizeOfImage
			ret.SizeOfHeaders = h.SizeOfHeaders
			ret.CheckSum = h.CheckSum
			ret.Subsystem = h.Subsystem
			ret.DllCharacteristics = h.DllCharacteristics
			ret.SizeOfStackReserve = uint64(h.SizeOfStackReserve)
			ret.SizeOfStackCommit = uint64(h.SizeOfStackCommit)
			ret.SizeOfHeapReserve = uint64(h.SizeOfHeapReserve)
			ret.SizeOfHeapCommit = uint64(h.SizeOfHeapCommit)
			ret.LoaderFlags = h.LoaderFlags
			ret.NumberOfRvaAndSizes = h.NumberOfRvaAndSizes
			ret.DataDirectory = h.DataDirectory[:]
		case *pe.OptionalHeader64:
			h := p.File.OptionalHeader.(*pe.OptionalHeader64)
			ret.MajorLinkerVersion = h.MajorLinkerVersion
			ret.MinorLinkerVersion = h.MinorLinkerVersion
			ret.SizeOfCode = h.SizeOfCode
			ret.SizeOfInitializedData = h.SizeOfInitializedData
			ret.SizeOfUninitializedData = h.SizeOfUninitializedData
			ret.AddressOfEntryPoint = h.AddressOfEntryPoint
			ret.BaseOfCode = h.BaseOfCode
			ret.ImageBase = h.ImageBase
			ret.SectionAlignment = h.SectionAlignment
			ret.FileAlignment = h.FileAlignment
			ret.MajorOperatingSystemVersion = h.MajorOperatingSystemVersion
			ret.MinorOperatingSystemVersion = h.MinorOperatingSystemVersion
			ret.MajorImageVersion = h.MajorImageVersion
			ret.MinorImageVersion = h.MinorImageVersion
			ret.MajorSubsystemVersion = h.MajorSubsystemVersion
			ret.MinorSubsystemVersion = h.MinorSubsystemVersion
			ret.Win32VersionValue = h.Win32VersionValue
			ret.SizeOfImage = h.SizeOfImage
			ret.SizeOfHeaders = h.SizeOfHeaders
			ret.CheckSum = h.CheckSum
			ret.Subsystem = h.Subsystem
			ret.DllCharacteristics = h.DllCharacteristics
			ret.SizeOfStackReserve = h.SizeOfStackReserve
			ret.SizeOfStackCommit = h.SizeOfStackCommit
			ret.SizeOfHeapReserve = h.SizeOfHeapReserve
			ret.SizeOfHeapCommit = h.SizeOfHeapCommit
			ret.LoaderFlags = h.LoaderFlags
			ret.NumberOfRvaAndSizes = h.NumberOfRvaAndSizes
			ret.DataDirectory = h.DataDirectory[:]
		}
	}

	return &ret
}

func (p *PeFile) isOptionHeader64() bool {
	f := p.File
	if f.OptionalHeader != nil {
		return f.Machine == pe.IMAGE_FILE_MACHINE_AMD64
	}

	return false
}

func (p *PeFile) WriteTo(w io.Writer) (err error) {
	fileHeader := p.File.FileHeader
	fileAlignment := p.fileAlignment
	size := uint32(binary.Size(fileHeader))
	size += uint32(p.File.SizeOfOptionalHeader)
	if p.File.OptionalHeader != nil {
		size += uint32(len(peHeader))
	}

	size += uint32(int(fileHeader.NumberOfSections) * binary.Size(pe.SectionHeader32{}))
	if fileAlignment > 1 && size%fileAlignment != 0 {
		size = size - size%fileAlignment + fileAlignment
	}

	if p.File.OptionalHeader != nil {
		switch p.File.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			h := p.File.OptionalHeader.(*pe.OptionalHeader32)
			h.SizeOfHeaders = size
		case *pe.OptionalHeader64:
			h := p.File.OptionalHeader.(*pe.OptionalHeader64)
			h.SizeOfHeaders = size
		}
	}

	sections := buildSectionRaw(p.File, size, fileAlignment)
	if fileHeader.NumberOfSymbols > 0 {
		fileHeader.PointerToSymbolTable = sections.rawDataEnd
	}

	headers := []interface{}{peHeader, &fileHeader, p.File.OptionalHeader, sections.header}
	if p.File.OptionalHeader == nil { //obj hasn't option header
		headers[0] = nil
	}

	var buf bytes.Buffer
	for _, v := range headers {
		if v != nil {
			if err = binary.Write(&buf, binary.LittleEndian, v); err != nil {
				return
			}
		}
	}

	if uint32(buf.Len()) < size {
		data := make([]byte, int(size)-buf.Len())
		buf.Write(data)
	}
	if _, err = buf.WriteTo(w); err == nil {
		if err = p.writeSection(w, sections.data, fileAlignment); err == nil {
			err = p.writeSymbolAndStringTable(w)
		}
	}

	return
}

func (p *PeFile) writeSection(w io.Writer, data []sectionRawData, alignment uint32) (err error) {
	if alignment < 16 {
		alignment = 16
	}
	blank := make([]byte, alignment)
	sections := p.File.Sections
	from := data[0].pos
	var size int64

	for _, d := range data {
		v := sections[d.index]
		if from < d.pos {
			if err = writeBlank(w, blank, int(d.pos-from)); err != nil {
				break
			}

			from = d.pos
		}

		if d.data == nil {
			r := v.Open()
			size, err = io.Copy(w, r)
			if err != nil {
				break
			}
		} else {
			if err = binary.Write(w, binary.LittleEndian, d.data); err != nil {
				break
			}
			size = int64(d.size)
		}

		sizeAdd := int(d.size) - int(size)
		if sizeAdd > 0 {
			if err = writeBlank(w, blank, sizeAdd); err != nil {
				break
			}
		}
		from += d.size
	}

	return
}

func writeBlank(w io.Writer, blank []byte, size int) (err error) {
	if size <= len(blank) {
		_, err = w.Write(blank[:size])
	} else {
		for i := 0; i < size; i += len(blank) {
			next := size - i
			if next > len(blank) {
				next = len(blank)
			}

			if _, err = w.Write(blank[:next]); err != nil {
				break
			}
		}
	}

	return
}

func searchString(str string, st []byte) uint32 {
	size := len(str)
	stSize := len(st)
	from := 0

	for i := 0; i < stSize; i++ {
		if st[i] == 0 {
			if i-from == size && bytes.Compare([]byte(str), st[from:i]) == 0 {
				return uint32(from + 4)
			}

			from = i + 1
		}
	}

	if from < stSize && stSize-from == size && bytes.Compare([]byte(str), st[from:]) == 0 {
		return uint32(from + 4)
	}

	return 0
}

func (p *PeFile) writeSymbolAndStringTable(w io.Writer) (err error) {
	if p.File.COFFSymbols != nil {
		err = binary.Write(w, binary.LittleEndian, p.File.COFFSymbols)
	}

	if err == nil && p.File.StringTable != nil {
		size := uint32(len(p.File.StringTable) + 4)
		if err = binary.Write(w, binary.LittleEndian, &size); err == nil {
			_, err = w.Write(p.File.StringTable)
		}
	}

	return
}

func (p *PeFile) Close() {
	if p.File != nil {
		p.File.Close()
	}
}

func (p *PeFile) AddSection(name string, data []byte, characteristics uint32) {
	s := customSection{name: name, data: data, characteristics: characteristics}
	if p.File.OptionalHeader != nil {
		s.virtualAddress, s.virtualSize = p.addSectionAllocAddress(len(data))
	}

	p.mySections = append(p.mySections, s)
	p.File.NumberOfSections++
	p.sectionChanged()
}

func (p *PeFile) addSectionAllocAddress(need int) (addr, size uint32) {
	addr = uint32(p.va.Alloc(uint64(need)))
	size = uint32(need)
	align := p.sectionAlignment

	if align > 1 && size%align != 0 {
		size = size - size%align + align
	}

	return
}

func (p *PeFile) RemoveSection(name string) bool {
	i := 0
	s := p.mySections
	found := false

	for ; i < len(s); i++ {
		if s[i].name == name {
			if p.va != nil {
				p.va.Remove(uint64(s[i].virtualAddress), uint64(s[i].virtualSize))
			}

			p.mySections = append(s[:i], s[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		s := p.File.Sections
		for i = 0; i < len(s); i++ {
			if s[i].Name == name {
				if p.va != nil {
					p.va.Remove(uint64(s[i].VirtualAddress), uint64(s[i].VirtualSize))
				}
				p.File.Sections = append(s[:i], s[i+1:]...)
				found = true
				break
			}
		}
	}

	if found {
		p.File.NumberOfSections--
		p.sectionChanged()
	}

	return found
}

func (p *PeFile) alignSize(size uint32, file bool) uint32 {
	align := p.fileAlignment
	if !file {
		align = p.sectionAlignment
	}

	if size%align != 0 {
		size = size - size%align + align
	}

	return size
}

func (p *PeFile) sectionChanged() {
	code := uint32(0)
	data := uint32(0)
	bss := uint32(0)
	size := uint32(0)

	if p.File.OptionalHeader != nil {
		s := p.File.Sections
		for _, v := range s {
			c := v.Characteristics
			if (c & IMAGE_SCN_CNT_CODE) != 0 {
				code += p.alignSize(v.Size, true)
			}

			if (c & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
				data += p.alignSize(v.Size, true)
			}

			if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
				bss += p.alignSize(v.Size, true)
			}

			sizeCur := p.alignSize(v.VirtualAddress+v.VirtualSize, false)
			if sizeCur > size {
				size = sizeCur
			}
		}

		mySections := p.mySections
		for _, v := range mySections {
			c := v.characteristics
			if (c & IMAGE_SCN_CNT_CODE) != 0 {
				code += p.alignSize(uint32(len(v.data)), true)
			}

			if (c & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0 {
				data += p.alignSize(uint32(len(v.data)), true)
			}

			if (c & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0 {
				bss += p.alignSize(uint32(len(v.data)), true)
			}

			sizeCur := p.alignSize(v.virtualAddress+v.virtualSize, false)
			if sizeCur > size {
				size = sizeCur
			}
		}

		switch p.File.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			h := p.File.OptionalHeader.(*pe.OptionalHeader32)
			h.SizeOfCode = code
			h.SizeOfInitializedData = data
			h.SizeOfUninitializedData = bss
			h.SizeOfImage = size
			h.CheckSum = 0
		case *pe.OptionalHeader64:
			h := p.File.OptionalHeader.(*pe.OptionalHeader64)
			h.SizeOfCode = code
			h.SizeOfInitializedData = data
			h.SizeOfUninitializedData = bss
			h.SizeOfImage = size
			h.CheckSum = 0
		}
	}
}

func (p *PeFile) ResetFileAlignment(align uint32) {
	if align != p.fileAlignment {
		p.fileAlignment = align

		if p.File.OptionalHeader != nil {
			switch p.File.OptionalHeader.(type) {
			case *pe.OptionalHeader32:
				h := p.File.OptionalHeader.(*pe.OptionalHeader32)
				h.FileAlignment = align
			case *pe.OptionalHeader64:
				h := p.File.OptionalHeader.(*pe.OptionalHeader64)
				h.FileAlignment = align
			}

			p.sectionChanged()
		}
	}
}

func (p *PeFile) load() {
	if p.File.OptionalHeader != nil {
		p.va = container.NewScope()
		for _, s := range p.File.Sections {
			p.va.Insert(uint64(s.VirtualAddress), uint64(s.VirtualSize))
		}

		if p.isOptionHeader64() {
			h := p.File.OptionalHeader.(*pe.OptionalHeader64)
			p.fileAlignment = h.FileAlignment
			p.sectionAlignment = h.SectionAlignment
		} else {
			h := p.File.OptionalHeader.(*pe.OptionalHeader32)
			p.fileAlignment = h.FileAlignment
			p.sectionAlignment = h.SectionAlignment
		}
	} else {
		p.fileAlignment = 1
		p.sectionAlignment = 1
	}
}

func New(r io.ReaderAt) (*PeFile, error) {
	return toFile(pe.NewFile(r))
}

func Open(name string) (*PeFile, error) {
	return toFile(pe.Open(name))
}

func toFile(f *pe.File, err error) (*PeFile, error) {
	if err == nil {
		ret := &PeFile{File: f}
		ret.load()

		return ret, nil
	} else {
		return nil, err
	}
}
