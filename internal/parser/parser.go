package parser

import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/butwhoistrace/strings/internal"
)

func ParseSections(filepath string) []internal.SectionInfo {
	sections := parsePE(filepath)
	if len(sections) == 0 {
		sections = parseELF(filepath)
	}
	return sections
}

func FormatType(filepath string) string {
	f, err := os.Open(filepath)
	if err != nil {
		return ""
	}
	defer f.Close()
	magic := make([]byte, 4)
	f.Read(magic)
	if magic[0] == 'M' && magic[1] == 'Z' {
		return "PE"
	}
	if bytes.Equal(magic, []byte{0x7f, 'E', 'L', 'F'}) {
		return "ELF"
	}
	return ""
}

func GetSectionForOffset(sections []internal.SectionInfo, offset int64) string {
	for _, sec := range sections {
		if offset >= sec.Offset && offset < sec.Offset+sec.Size {
			return sec.Name
		}
	}
	return ""
}

func parsePE(filepath string) []internal.SectionInfo {
	f, err := os.Open(filepath)
	if err != nil {
		return nil
	}
	defer f.Close()

	magic := make([]byte, 2)
	f.Read(magic)
	if magic[0] != 'M' || magic[1] != 'Z' {
		return nil
	}

	f.Seek(0x3C, 0)
	var peOffset uint32
	binary.Read(f, binary.LittleEndian, &peOffset)

	f.Seek(int64(peOffset), 0)
	sig := make([]byte, 4)
	f.Read(sig)
	if !bytes.Equal(sig, []byte{'P', 'E', 0, 0}) {
		return nil
	}

	f.Seek(2, 1)
	var numSections uint16
	binary.Read(f, binary.LittleEndian, &numSections)
	f.Seek(12, 1)
	var optionalSize uint16
	binary.Read(f, binary.LittleEndian, &optionalSize)
	f.Seek(2, 1)
	f.Seek(int64(optionalSize), 1)

	var sections []internal.SectionInfo
	for i := 0; i < int(numSections); i++ {
		header := make([]byte, 40)
		n, _ := f.Read(header)
		if n < 40 {
			break
		}
		nameBytes := bytes.TrimRight(header[:8], "\x00")
		name := string(nameBytes)
		virtualAddr := binary.LittleEndian.Uint32(header[12:16])
		rawSize := binary.LittleEndian.Uint32(header[16:20])
		rawOffset := binary.LittleEndian.Uint32(header[20:24])

		sections = append(sections, internal.SectionInfo{
			Name:           name,
			Offset:         int64(rawOffset),
			Size:           int64(rawSize),
			VirtualAddress: uint64(virtualAddr),
		})
	}
	return sections
}

func parseELF(filepath string) []internal.SectionInfo {
	data, err := os.ReadFile(filepath)
	if err != nil || len(data) < 64 {
		return nil
	}
	if !bytes.Equal(data[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil
	}

	eiClass := data[4]
	eiData := data[5]
	is64 := eiClass == 2

	var order binary.ByteOrder
	if eiData == 1 {
		order = binary.LittleEndian
	} else {
		order = binary.BigEndian
	}

	var shoff uint64
	var shentsize, shnum, shstrndx uint16

	if is64 {
		shoff = order.Uint64(data[0x28:0x30])
		shentsize = order.Uint16(data[0x3A:0x3C])
		shnum = order.Uint16(data[0x3C:0x3E])
		shstrndx = order.Uint16(data[0x3E:0x40])
	} else {
		shoff = uint64(order.Uint32(data[0x20:0x24]))
		shentsize = order.Uint16(data[0x2E:0x30])
		shnum = order.Uint16(data[0x30:0x32])
		shstrndx = order.Uint16(data[0x32:0x34])
	}

	if shoff == 0 || shnum == 0 || int(shoff) >= len(data) {
		return nil
	}

	strIdx := int(shoff) + int(shstrndx)*int(shentsize)
	if strIdx+int(shentsize) > len(data) {
		return nil
	}

	var strtabOff, strtabSz uint64
	if is64 {
		strtabOff = order.Uint64(data[strIdx+24 : strIdx+32])
		strtabSz = order.Uint64(data[strIdx+32 : strIdx+40])
	} else {
		strtabOff = uint64(order.Uint32(data[strIdx+16 : strIdx+20]))
		strtabSz = uint64(order.Uint32(data[strIdx+20 : strIdx+24]))
	}

	if int(strtabOff+strtabSz) > len(data) {
		return nil
	}
	strtab := data[strtabOff : strtabOff+strtabSz]

	var sections []internal.SectionInfo
	for i := 0; i < int(shnum); i++ {
		off := int(shoff) + i*int(shentsize)
		if off+int(shentsize) > len(data) {
			break
		}

		shName := order.Uint32(data[off : off+4])
		var shAddr, shOff, shSize uint64
		if is64 {
			shAddr = order.Uint64(data[off+16 : off+24])
			shOff = order.Uint64(data[off+24 : off+32])
			shSize = order.Uint64(data[off+32 : off+40])
		} else {
			shAddr = uint64(order.Uint32(data[off+12 : off+16]))
			shOff = uint64(order.Uint32(data[off+16 : off+20]))
			shSize = uint64(order.Uint32(data[off+20 : off+24]))
		}

		name := ""
		if int(shName) < len(strtab) {
			end := bytes.IndexByte(strtab[shName:], 0)
			if end >= 0 {
				name = string(strtab[shName : shName+uint32(end)])
			}
		}

		if shSize > 0 && name != "" {
			sections = append(sections, internal.SectionInfo{
				Name:           name,
				Offset:         int64(shOff),
				Size:           int64(shSize),
				VirtualAddress: shAddr,
			})
		}
	}
	return sections
}
