package parser

import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/butwhoistrace/strings/internal"
)

func ParseSections(filepath string) (sections []internal.SectionInfo) {
	defer func() {
		if r := recover(); r != nil {
			sections = nil
		}
	}()
	sections = parsePE(filepath)
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
	n, err := f.Read(magic)
	if err != nil || n < 4 {
		return ""
	}
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
	if n, err := f.Read(magic); err != nil || n < 2 {
		return nil
	}
	if magic[0] != 'M' || magic[1] != 'Z' {
		return nil
	}

	if _, err := f.Seek(0x3C, 0); err != nil {
		return nil
	}
	var peOffset uint32
	if err := binary.Read(f, binary.LittleEndian, &peOffset); err != nil {
		return nil
	}

	// Validate peOffset is within reasonable bounds
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	if int64(peOffset)+4 > info.Size() {
		return nil
	}

	if _, err := f.Seek(int64(peOffset), 0); err != nil {
		return nil
	}
	sig := make([]byte, 4)
	if n, err := f.Read(sig); err != nil || n < 4 {
		return nil
	}
	if !bytes.Equal(sig, []byte{'P', 'E', 0, 0}) {
		return nil
	}

	if _, err := f.Seek(2, 1); err != nil {
		return nil
	}
	var numSections uint16
	if err := binary.Read(f, binary.LittleEndian, &numSections); err != nil {
		return nil
	}
	// Cap numSections to prevent resource exhaustion
	if numSections > 256 {
		return nil
	}

	if _, err := f.Seek(12, 1); err != nil {
		return nil
	}
	var optionalSize uint16
	if err := binary.Read(f, binary.LittleEndian, &optionalSize); err != nil {
		return nil
	}
	if _, err := f.Seek(2, 1); err != nil {
		return nil
	}
	if _, err := f.Seek(int64(optionalSize), 1); err != nil {
		return nil
	}

	var sections []internal.SectionInfo
	for i := 0; i < int(numSections); i++ {
		header := make([]byte, 40)
		n, err := f.Read(header)
		if err != nil || n < 40 {
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
		if len(data) < 0x40 {
			return nil
		}
		shoff = order.Uint64(data[0x28:0x30])
		shentsize = order.Uint16(data[0x3A:0x3C])
		shnum = order.Uint16(data[0x3C:0x3E])
		shstrndx = order.Uint16(data[0x3E:0x40])
	} else {
		if len(data) < 0x34 {
			return nil
		}
		shoff = uint64(order.Uint32(data[0x20:0x24]))
		shentsize = order.Uint16(data[0x2E:0x30])
		shnum = order.Uint16(data[0x30:0x32])
		shstrndx = order.Uint16(data[0x32:0x34])
	}

	if shoff == 0 || shnum == 0 || shentsize == 0 || int64(shoff) >= int64(len(data)) {
		return nil
	}
	// Cap shnum to prevent resource exhaustion
	if shnum > 1024 {
		return nil
	}

	// Validate string table index bounds with overflow-safe arithmetic
	strIdx := int64(shoff) + int64(shstrndx)*int64(shentsize)
	if strIdx < 0 || strIdx+int64(shentsize) > int64(len(data)) {
		return nil
	}

	var strtabOff, strtabSz uint64
	if is64 {
		if int64(strIdx)+40 > int64(len(data)) {
			return nil
		}
		strtabOff = order.Uint64(data[strIdx+24 : strIdx+32])
		strtabSz = order.Uint64(data[strIdx+32 : strIdx+40])
	} else {
		if int64(strIdx)+24 > int64(len(data)) {
			return nil
		}
		strtabOff = uint64(order.Uint32(data[strIdx+16 : strIdx+20]))
		strtabSz = uint64(order.Uint32(data[strIdx+20 : strIdx+24]))
	}

	if strtabOff > uint64(len(data)) || strtabSz > uint64(len(data)) || strtabOff+strtabSz > uint64(len(data)) {
		return nil
	}
	strtab := data[strtabOff : strtabOff+strtabSz]

	var sections []internal.SectionInfo
	for i := 0; i < int(shnum); i++ {
		off := int64(shoff) + int64(i)*int64(shentsize)
		if off < 0 || off+int64(shentsize) > int64(len(data)) {
			break
		}

		shName := order.Uint32(data[off : off+4])
		var shAddr, shOff, shSize uint64
		if is64 {
			if off+40 > int64(len(data)) {
				break
			}
			shAddr = order.Uint64(data[off+16 : off+24])
			shOff = order.Uint64(data[off+24 : off+32])
			shSize = order.Uint64(data[off+32 : off+40])
		} else {
			if off+24 > int64(len(data)) {
				break
			}
			shAddr = uint64(order.Uint32(data[off+12 : off+16]))
			shOff = uint64(order.Uint32(data[off+16 : off+20]))
			shSize = uint64(order.Uint32(data[off+20 : off+24]))
		}

		name := ""
		if int(shName) < len(strtab) {
			end := bytes.IndexByte(strtab[shName:], 0)
			if end >= 0 && int(shName)+end <= len(strtab) {
				name = string(strtab[shName : int(shName)+end])
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
