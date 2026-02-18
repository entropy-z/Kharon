package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

type BofPacker struct {
	buffer bytes.Buffer
}

func LoadExtModule( src string, file string, arch string) ([]byte, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %v", err)
	}

	var mod_path string

	switch src {
	case "src_core":
		mod_path = filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", src, "dist", fmt.Sprintf("%s.%s.o", file, arch))
	case "src_modules":
		mod_path = ""
	}

	fmt.Printf("DEBUG: Loading BOF module from: %s\n", mod_path)

	mod_content, err := os.ReadFile(mod_path)
	if err != nil {
		return nil, fmt.Errorf("failed to read BOF module '%s': %v", mod_path, err)
	}

	fmt.Printf("DEBUG: BOF module loaded (%d bytes)\n", len(mod_content))
	return mod_content, nil
}

func NewBofPacker() *BofPacker {
	return &BofPacker{}
}

func (bp *BofPacker) AddInt32(val int32) {
	binary.Write(&bp.buffer, binary.LittleEndian, val)
}

func (bp *BofPacker) AddInt16(val int16) {
	binary.Write(&bp.buffer, binary.LittleEndian, val)
}

func (bp *BofPacker) AddInt8(val int8) {
	binary.Write(&bp.buffer, binary.LittleEndian, val)
}

func (bp *BofPacker) AddString(val string) {
	data := []byte(val)
	binary.Write(&bp.buffer, binary.LittleEndian, int32(len(data)))
	bp.buffer.Write(data)
}

func (bp *BofPacker) AddWString(val string) {
	utf16Bytes := utf16.Encode([]rune(val))
	binary.Write(&bp.buffer, binary.LittleEndian, int32(len(utf16Bytes)*2))
	for _, r := range utf16Bytes {
		binary.Write(&bp.buffer, binary.LittleEndian, r)
	}
}

func (bp *BofPacker) AddBytes(val []byte) {
	binary.Write(&bp.buffer, binary.LittleEndian, int32(len(val)))
	bp.buffer.Write(val)
}

func (bp *BofPacker) Bytes() []byte {
	return bp.buffer.Bytes()
}

func (bp *BofPacker) Reset() {
	bp.buffer.Reset()
}

func PackExtData(args ...interface{}) ([]byte, error) {
	bp := NewBofPacker()

	for _, arg := range args {
		switch v := arg.(type) {
		case int:
			bp.AddInt32(int32(v))
		case int32:
			bp.AddInt32(v)
		case int16:
			bp.AddInt16(v)
		case int8:
			bp.AddInt8(v)
		case string:
			bp.AddString(v)
		case []byte:
			bp.AddBytes(v)
		default:
			return nil, fmt.Errorf("unsupported type for BOF packing: %T", v)
		}
	}

	data := bp.Bytes()
	
	result := make([]byte, 4+len(data))
	
	binary.LittleEndian.PutUint32(result[0:4], uint32(len(data)))
	
	copy(result[4:], data)
	
	return result, nil
}

func PackExtDataString(str1 string, ACP int) ([]byte) {
	return []byte(ConvertUTF8toCp(str1, ACP))
}

func PackExtDataWChar(str1 string, ACP int) ([]byte) {
	return ConvertStringToWCharNullTerminated(ConvertUTF8toCp(str1, ACP))
}

type Packer struct {
	buffer []byte
}

func CreatePacker(buffer []byte) *Packer {
	return &Packer{
		buffer: buffer,
	}
}

func (p *Packer) Size() uint {
	return uint(len(p.buffer))
}

func (p *Packer) CheckPacker(types []string) bool {

	packerSize := p.Size()

	for _, t := range types {
		switch t {

		case "byte":
			if packerSize < 1 {
				return false
			}
			packerSize -= 1

		case "word":
			if packerSize < 2 {
				return false
			}
			packerSize -= 2

		case "int":
			if packerSize < 4 {
				return false
			}
			packerSize -= 4

		case "long":
			if packerSize < 8 {
				return false
			}
			packerSize -= 8

		case "array":
			if packerSize < 4 {
				return false
			}

			index := p.Size() - packerSize
			value := make([]byte, 4)
			copy(value, p.buffer[index:index+4])
			length := uint(binary.BigEndian.Uint32(value))
			packerSize -= 4

			if packerSize < length {
				return false
			}
			packerSize -= length
		}
	}
	return true
}

func (p *Packer) ParseInt8() uint8 {
	var value = make([]byte, 1)

	if p.Size() >= 1 {
		if p.Size() == 1 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:1])
			p.buffer = p.buffer[1:]
		}
	} else {
		return 0
	}

	return value[0]
}

func (p *Packer) ParseInt16() uint16 {
	var value = make([]byte, 2)

	if p.Size() >= 2 {
		if p.Size() == 2 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:2])
			p.buffer = p.buffer[2:]
		}
	} else {
		return 0
	}

	return binary.BigEndian.Uint16(value)
}

func (p *Packer) ParseInt32() uint {
	var value = make([]byte, 4)

	if p.Size() >= 4 {
		if p.Size() == 4 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:4])
			p.buffer = p.buffer[4:]
		}
	} else {
		return 0
	}

	return uint(binary.BigEndian.Uint32(value))
}

func (p *Packer) ParseInt64() uint64 {
	var value = make([]byte, 8)

	if p.Size() >= 8 {
		if p.Size() == 8 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:8])
			p.buffer = p.buffer[8:]
		}
	} else {
		return 0
	}

	return binary.BigEndian.Uint64(value)
}

func (p *Packer) ParsePad(size uint) []byte {
	if p.Size() < size {
		return make([]byte, 0)
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return b
	}
}

func (p *Packer) ParseBytes() []byte {
	size := p.ParseInt32()

	if p.Size() < size {
		return make([]byte, 0)
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return b
	}
}

func (p *Packer) ParseString() string {
	size := p.ParseInt32()

	if p.Size() < size {
		return ""
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return string(bytes.Trim(b, "\x00"))
	}
}

func PackArray(array []interface{}) ([]byte, error) {
	var packData []byte
	//fmt.printf("=== PACK ARRAY START ===\n")
	//fmt.printf("Elements: %d\n", len(array))

	for i := range array {
		//fmt.printf("[Elem %d]: ", i)

		switch v := array[i].(type) {

		case []byte:
			val := array[i].([]byte)
			packData = append(packData, val...)
			//fmt.printf("[%d bytes]", len(val))

		case string:
			size := make([]byte, 4)
			val := array[i].(string)
			if len(val) != 0 {
				if !strings.HasSuffix(val, "\x00") {
					val += "\x00"
				}
			}
			binary.LittleEndian.PutUint32(size, uint32(len(val)))
			packData = append(packData, size...)
			packData = append(packData, []byte(val)...)
			//fmt.printf("[4 bytes size][%d bytes data]", len(val))

		case []uint16:
			size := make([]byte, 4)

			needsTerminator := true
			if len(v) > 0 && v[len(v)-1] == 0 {
				needsTerminator = false
			}

			totalSize := len(v) * 2
			if needsTerminator {
				totalSize += 2
			}

			val := make([]byte, totalSize)

			for i, wchar := range v {
				val[i*2] = byte(wchar)
				val[i*2+1] = byte(wchar >> 8)
			}

			if needsTerminator && len(v) > 0 {
				val[len(v)*2] = 0x00
				val[len(v)*2+1] = 0x00
			}

			fmt.Printf("out %s\n", val)

			binary.LittleEndian.PutUint32(size, uint32(len(val)))
			packData = append(packData, size...)
			packData = append(packData, val...)

		case int:
			num := make([]byte, 4)
			val := array[i].(int)
			binary.LittleEndian.PutUint32(num, uint32(val))
			packData = append(packData, num...)
			//fmt.printf("[4 bytes]: %d", val)

		case uint:
			num := make([]byte, 4)
			val := array[i].(int)
			binary.LittleEndian.PutUint32(num, uint32(val))
			packData = append(packData, num...)
			//fmt.printf("[4 bytes]: %d", val)

		case uint32:
			num := make([]byte, 4)
			val := array[i].(int)
			binary.LittleEndian.PutUint32(num, uint32(val))
			packData = append(packData, num...)
			//fmt.printf("[4 bytes]: %d", val)

		case int32:
			num := make([]byte, 4)
			val := array[i].(int)
			binary.LittleEndian.PutUint32(num, uint32(val))
			packData = append(packData, num...)
			//fmt.printf("[4 bytes]: %d", val)

		case int16:
			num := make([]byte, 2)
			val := array[i].(int16)
			binary.LittleEndian.PutUint16(num, uint16(val))
			packData = append(packData, num...)
			//fmt.printf("[2 bytes]: %d", val)

		case int8:
			num := make([]byte, 1)
			num[0] = byte(array[i].(int8))
			packData = append(packData, num...)
			//fmt.printf("[1 byte]: %d", num)

		case bool:
			var bt = make([]byte, 1)
			if array[i].(bool) {
				bt[0] = 1
			}
			packData = append(packData, bt...)
			//fmt.printf("[1 byte]: %d", bt)

		default:
			//fmt.printf("[ERROR: unknown type]")
			return nil, errors.New("PackArray unknown type")
		}

		//fmt.printf(" → Total: %d bytes\n", len(packData))
	}

	//fmt.printf("=== PACK ARRAY END ===\n")
	//fmt.printf("Final size: %d bytes\n", len(packData))
	//fmt.printf("Final structure complete\n")
	return packData, nil
}
