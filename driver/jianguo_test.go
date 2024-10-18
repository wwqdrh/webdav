package driver

import (
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func testGetJianguoDriver(t *testing.T) (IDriver, bool) {
	godotenv.Load("testdata/env")

	d := NewJianguoDriver(nil)
	d.Auth(os.Getenv("jianguousername"), os.Getenv("jianguopassword"))
	if !d.IsAuth() {
		t.Skip("no webdav env, skip")
		return d, false
	}
	return d, true
}

func TestJianguoUpdateAndDelete(t *testing.T) {
	d, ok := testGetJianguoDriver(t)
	if !ok {
		return
	}

	if err := d.Update("testdata/upload.txt", "upload.txt"); err != nil {
		t.Error(err)
		return
	}

	if data, contentType, err := d.GetStat("upload.txt"); err != nil {
		t.Error(err)
		return
	} else if string(data) != "TEST UPLOAD DATA" {
		t.Error("内容错误")
		return
	} else if contentType != "text/plain" {
		t.Error("获取文件格式失败")
		return
	}

	if err := d.Delete("upload.txt"); err != nil {
		t.Error(err)
		return
	}
}

func TestJianguoList(t *testing.T) {
	d, ok := testGetJianguoDriver(t)
	if !ok {
		return
	}

	items, err := d.List("")
	if err != nil {
		t.Error(err)
		return
	}
	for _, item := range items {
		if item.Href == "" {
			t.Error("get list name is empty")
			return
		}
	}
}
