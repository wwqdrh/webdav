package webdav

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/net/webdav"
)

func TestNoSniffFileInfo_ContentType(t *testing.T) {
	testCases := []struct {
		name           string
		file           string
		expectedType   string
		expectedErrStr string
	}{
		{
			name:         "known extension",
			file:         "testdata/file.txt",
			expectedType: "text/plain; charset=utf-8",
		},
		{
			name:         "unknown extension",
			file:         "testdata/file.unknown",
			expectedType: "application/octet-stream",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := os.Stat(tc.file)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			contentType, err := NoSniffFileInfo{info}.ContentType(context.Background())
			if err != nil && tc.expectedErrStr == "" {
				t.Errorf("unexpected error: %v", err)
			} else if err != nil && err.Error() != tc.expectedErrStr {
				t.Errorf("expected error '%s', got '%v'", tc.expectedErrStr, err)
			} else if contentType != tc.expectedType {
				t.Errorf("expected content type '%s', got '%s'", tc.expectedType, contentType)
			}
		})
	}
}

func TestWebDavDir_Stat(t *testing.T) {
	dir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(dir)

	f, err := os.CreateTemp(dir, "file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f.Close()

	webdavDir := WebDavDir{Dir: webdav.Dir(dir)}

	webdavDir.NoSniff = true
	info, err := webdavDir.Stat(context.Background(), filepath.Base(f.Name()))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	} else if _, ok := info.(NoSniffFileInfo); !ok {
		t.Errorf("expected NoSniffFileInfo, got %T", info)
	}

	webdavDir.NoSniff = false
	info, err = webdavDir.Stat(context.Background(), filepath.Base(f.Name()))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	} else if _, ok := info.(NoSniffFileInfo); ok {
		t.Errorf("expected regular FileInfo, got NoSniffFileInfo")
	}
}
