package osutil

import "io/fs"

// RootDirFS returns the fs.FS rooted at the operating system's root.  On
// Windows it returns the fs.FS rooted at the volume of the system directory
// (usually, C:).
func RootDirFS() (fsys fs.FS) {
	return rootDirFS()
}
