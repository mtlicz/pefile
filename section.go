package pefile

import (
	"debug/pe"
	"sort"
	"strconv"
)

func buildSectionRaw(f *pe.File, headerSize uint32, align uint32) *sectionRaw {
	sections := f.Sections
	header := make([]pe.SectionHeader32, len(sections))
	stringTable := f.StringTable
	addString := false
	var data []sectionRawData

	for i, v := range sections {
		size := len(v.Name)
		s := &header[i]

		if size <= 8 {
			copy(s.Name[:], []byte(v.Name))
		} else {
			s.Name[0] = '/'
			index := searchString(v.Name, stringTable)
			if index == 0 { //需要添加
				addString = true
				index = uint32(len(stringTable) + 4)
				stringTable = append(stringTable, []byte(v.Name)...)
			}

			indexStr := strconv.Itoa(int(index))
			copy(s.Name[1:], []byte(indexStr))
		}

		s.VirtualSize = v.VirtualSize
		s.VirtualAddress = v.VirtualAddress
		s.SizeOfRawData = v.Size
		s.PointerToRawData = v.Offset
		s.PointerToRelocations = v.PointerToRelocations
		s.PointerToLineNumbers = v.PointerToLineNumbers
		s.NumberOfRelocations = v.NumberOfRelocations
		s.NumberOfLineNumbers = v.NumberOfLineNumbers
		s.Characteristics = v.Characteristics

		if v.Size > 0 {
			dataCur := sectionRawData{uint32(i), nil, v.Offset, v.Size}
			data = append(data, dataCur)
		}

		if v.NumberOfRelocations != 0 {
			dataSize := uint32(v.NumberOfRelocations) * uint32(10)
			dataCur := sectionRawData{uint32(i), v.Relocs, v.PointerToRelocations, dataSize}
			data = append(data, dataCur)
		}
	}

	if addString {
		f.StringTable = stringTable
	}

	sort.Slice(data, func(i, j int) bool { return data[i].pos < data[j].pos })
	from := headerSize
	for i, _ := range data {
		s := &data[i]
		h := &header[s.index]

		if s.data == nil && s.size%align != 0 {
			s.size = s.size - s.size%align + align
			if i+1 < len(data) && s.pos+s.size > data[i+1].pos {
				s.size = data[i+1].pos - s.pos
			}
		}

		if from < s.pos && s.pos-from < 16 { //靠齐引起的不一致.
			from = s.pos
		} else if s.pos != from {
			s.pos = from

			if s.data == nil && h.SizeOfRawData > 0 {
				h.PointerToRawData = from
			} else {
				switch s.data.(type) {
				case []pe.Reloc:
					h.PointerToRelocations = from
				}
			}
		}
		from += s.size
	}

	return &sectionRaw{header, data, from}
}

type sectionRawData struct {
	index uint32
	data  interface{} //为nil表示为rawdata, []pe.Reloc表示为重定位信息.
	pos   uint32
	size  uint32
}

type sectionRaw struct {
	header     []pe.SectionHeader32
	data       []sectionRawData
	rawDataEnd uint32
}

type customSection struct {
	name            string
	data            []byte
	characteristics uint32
	virtualSize     uint32
	virtualAddress  uint32
}
