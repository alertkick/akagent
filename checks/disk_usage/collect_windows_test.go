//go:build windows

package disk_usage

import "testing"

func TestCollectFilesystemsWindows(t *testing.T) {
	fs, err := collectFilesystems()
	if err != nil {
		t.Fatalf("collectFilesystems: %v", err)
	}
	if len(fs) == 0 {
		t.Fatal("expected at least one filesystem (C:)")
	}
	for _, f := range fs {
		if f.totalBytes == 0 {
			t.Errorf("%s reported zero total bytes", f.mountPoint)
		}
		if f.usedBytes > f.totalBytes {
			t.Errorf("%s used > total", f.mountPoint)
		}
	}
}

func TestSanitizeMountPathWindows(t *testing.T) {
	cases := map[string]string{
		`C:\`:      "c",
		`D:\data`:  "d_data",
		`E:\a b\c`: "e_a_b_c",
	}
	for in, want := range cases {
		if got := sanitizeMountPath(in); got != want {
			t.Errorf("sanitizeMountPath(%q) = %q, want %q", in, got, want)
		}
	}
}
