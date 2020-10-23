package pefile

import (
	"bytes"
	"io/ioutil"
	"testing"
)

type rebuildItem struct {
	name       string
	headerType int
}

var rebuildItems = []rebuildItem{
	{"hello_gcc_exe", 0x80},
	{"hello_gcc_obj", 0x80},
	{"hello_vc_exe", 0x100},
	{"hello_vc_obj", 0xb8},
}

func TestExeWriteTo(t *testing.T) {
	for _, v := range rebuildItems {

		fileName := "testdata/" + v.name
		f, err := Open("testdata/" + v.name)

		if err != nil {
			t.Fatalf("Open failed: %v", err)
		} else {
			defer f.Close()
			var buf bytes.Buffer

			switch v.headerType {
			case 0x80:
				peHeader = peHeader80
			case 0xb8:
				peHeader = peHeaderB8
			case 0x100:
				peHeader = peHeader100
			}

			if err = f.WriteTo(&buf); err != nil {
				t.Fatalf("WriteTo buf failed: %v", err)
			} else {
				if data, err := ioutil.ReadFile(fileName); err != nil {
					t.Fatalf("read %v failed: %v", fileName, err)
				} else {
					bufData := buf.Bytes()
					if len(data) != len(bufData) {
						ioutil.WriteFile(v.name, bufData, 0)
						t.Fatalf("%v size should: %v, get: %v\n", v.name, len(data), len(bufData))
					} else if bytes.Compare(data, bufData) != 0 {
						ioutil.WriteFile(v.name, bufData, 0)
						t.Fatalf("%v data error\n", v.name)
					}
				}
			}
		}
	}
}
