package osutil

import "io/fs"

// RootDirFS returns the fs.FS rooted at the operating system's root.  On
// Windows it returns the fs.FS rooted at the volume of the system directory
// (usually, C:).
//
// TODO(e.burkov):  Move to golibs.
func RootDirFS() (fsys fs.FS) {
	return rootDirFS()
}
