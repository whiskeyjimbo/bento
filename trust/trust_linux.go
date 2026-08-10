//go:build linux

package trust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// attrMissing reports the errno a getxattr of an absent attribute answers with. Linux says
// ENODATA; the other platforms this builds for have a distinct ENOATTR that ENODATA does
// not alias, and reading that as a real failure would report a private directory as one
// somebody else can write.
func attrMissing(err error) bool { return errors.Is(err, unix.ENODATA) }

// manifestLocation is the path an open manifest actually came from, read back from the
// kernel's own name for the descriptor rather than the name it was opened by.
func manifestLocation(f *os.File) (string, error) {
	target, err := os.Readlink(procFD(int(f.Fd())))
	if err != nil {
		return "", noProcError(err)
	}
	return target, nil
}

// pathDirs walks path one component at a time and returns facts for every directory the
// resolution read a component from, nearest first, for every symlink it followed, and the
// name the last hop left -
// the manifest's own name at the location the walk landed in. Every one of them can decide which file
// the path reaches - a directory that holds a symlink repoints it at a file of its owner's
// choosing, and a directory anywhere above renames a level aside - so the check has to see
// all of them, not only the ones in the name it was given or the ones above where it landed.
// An intermediate symlink puts its target's ancestors in neither.
//
// The walk is done with descriptors rather than strings for the two things strings get
// wrong. `..` is resolved by the kernel against the directory actually reached, where
// cleaning it lexically after a symlink names a directory the walk never entered - and the
// failure mode of getting that wrong is silently missing a directory, which is the whole
// thing this exists to catch. And each directory's facts come from fstat of the descriptor
// the next component was read from, so nothing can be swapped between the two.
//
// A final component that is not there is not an error: profile walks the place a manifest
// is about to be written, and a dangling link at that name still has to be followed to the
// name it stands for rather than replaced. Every directory above it must exist.
func pathDirs(path string) (dirs, links []fileFacts, leaf string, err error) {
	// Not filepath.Abs, which cleans: it would delete a `..` lexically, and a `..` that
	// follows a symlink names a different directory cleaned than walked - the very thing
	// this walk exists to resolve properly.
	abs := path
	if !filepath.IsAbs(abs) {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, nil, "", err
		}
		abs = cwd + "/" + abs
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, "", err
	}
	defer unix.Close(root)

	dirfd, at := root, "/"
	// The descriptor the walk is standing on, closed however the walk ends: every error
	// below leaves one open otherwise, and the walk runs once per manifest load.
	defer func() { closeUnlessRoot(dirfd, root) }()
	rootFacts, err := fdFacts(root, "/")
	if err != nil {
		return nil, nil, "", err
	}
	out := []fileFacts{rootFacts}
	// The remaining components are a stack rather than a range, since resolving a symlink
	// splices its target's components in front of what is left to walk.
	rest := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for hops := 0; len(rest) > 0; {
		comp := rest[0]
		rest = rest[1:]
		switch comp {
		case "", ".":
			continue
		case "..":
			// No O_NOFOLLOW: `..` is not a symlink, and the kernel resolving it against the
			// directory the walk actually reached is the point of walking this way.
			up, err := unix.Openat(dirfd, "..", unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				return nil, nil, "", err
			}
			facts, err := fdFacts(up, filepath.Dir(at))
			if err != nil {
				unix.Close(up)
				return nil, nil, "", err
			}
			closeUnlessRoot(dirfd, root)
			dirfd, at = up, facts.path
			out = append(out, facts)
			continue
		}

		fd, err := unix.Openat(dirfd, comp, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && len(rest) == 0 {
			leaf = comp
			break
		}
		if err != nil {
			return nil, nil, "", &fs.PathError{Op: "openat", Path: filepath.Join(at, comp), Err: err}
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return nil, nil, "", err
		}
		switch mode := statMode(st.Mode); {
		case mode&fs.ModeSymlink != 0:
			hops++
			if hops > maxSymlinkHops {
				unix.Close(fd)
				return nil, nil, "", &fs.PathError{Op: "openat", Path: abs, Err: unix.ELOOP}
			}
			// The link's own owner, from the same fstat the type came from. Not fdFacts: a
			// symlink has no meaningful mode and carries no ACL, so there is nothing to read
			// through /proc for it.
			links = append(links, fileFacts{path: filepath.Join(at, comp), mode: mode, uid: st.Uid})
			link, err := readlinkat(dirfd, comp)
			unix.Close(fd)
			if err != nil {
				return nil, nil, "", err
			}
			// A relative target continues from the directory holding the link; an absolute
			// one restarts from the root, exactly as the kernel would resolve it.
			if strings.HasPrefix(link, "/") {
				closeUnlessRoot(dirfd, root)
				dirfd, at = root, "/"
			}
			rest = append(strings.Split(strings.Trim(link, "/"), "/"), rest...)
		case mode.IsDir():
			facts, err := fdFacts(fd, filepath.Join(at, comp))
			if err != nil {
				unix.Close(fd)
				return nil, nil, "", err
			}
			closeUnlessRoot(dirfd, root)
			dirfd, at = fd, facts.path
			out = append(out, facts)
		default:
			// A non-directory that is not the last component is a path that cannot resolve;
			// let whoever opens it say so rather than guessing at the errno here.
			unix.Close(fd)
			if len(rest) > 0 {
				return nil, nil, "", &fs.PathError{Op: "openat", Path: filepath.Join(at, comp), Err: unix.ENOTDIR}
			}
			leaf = comp
		}
	}
	if leaf == "" {
		return nil, nil, "", fmt.Errorf("%s names a directory, not a manifest", path)
	}
	slices.Reverse(out)
	return dedupeDirs(out), links, leaf, nil
}

// maxSymlinkHops matches the kernel's own ceiling, so a chain this walk refuses is one an
// open of the same path would refuse too.
const maxSymlinkHops = 40

func closeUnlessRoot(fd, root int) {
	if fd != root {
		unix.Close(fd)
	}
}

func readlinkat(dirfd int, comp string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirfd, comp, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

// dedupeDirs drops the repeats a walk produces on its own: `..` returns to a directory
// already entered, and a symlink's target shares every level above where it diverges from
// the name that reached it. The first mention wins, which is the nearest one.
func dedupeDirs(dirs []fileFacts) []fileFacts {
	seen := make(map[string]bool, len(dirs))
	out := dirs[:0]
	for _, d := range dirs {
		if !seen[d.path] {
			seen[d.path] = true
			out = append(out, d)
		}
	}
	return out
}

// fdFacts reads the facts of an already-open directory. The ACL is read through the
// descriptor's name in /proc rather than the path walked to it, since fgetxattr refuses an
// O_PATH descriptor and reopening for read needs a permission an ancestor may not grant.
func fdFacts(fd int, path string) (fileFacts, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fileFacts{}, err
	}
	facts := withGroup(fileFacts{path: path, mode: statMode(st.Mode), uid: st.Uid}, st.Gid)
	aclWrite, err := ACLNamedWrite(procFD(fd))
	if err != nil {
		return fileFacts{}, noProcError(err)
	}
	facts.aclWrite = aclWrite
	return facts, nil
}

// procFD names an open descriptor the way the kernel does. Both halves of the trust check
// read through such a name - the manifest's real location, and each directory's ACL, which
// fgetxattr will not read from an O_PATH descriptor - so every manifest load needs /proc
// mounted. Stricter than the advisory check it serves, and deliberately not softened: the
// only fallback is to resolve the path lexically, which is what produced a wrong verdict
// before it was removed. Nothing usable is refused by it either, since the userns probe,
// the mount table and the bridge's re-exec all read /proc too.
func procFD(fd int) string {
	return "/proc/self/fd/" + strconv.Itoa(fd)
}

// noProcError restates ENOENT from a procFD read as the unmounted /proc it can only mean -
// the descriptor is open, so nothing else makes its own name in /proc missing. The raw
// error names a descriptor number the caller never asked about.
func noProcError(err error) error {
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("/proc must be mounted to check where a manifest lives: %w", err)
	}
	return err
}

// statMode is st_mode as an fs.FileMode, carrying the bits the trust check reads: the type,
// the permissions, and setgid and sticky, each of which changes what the permissions mean.
func statMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFREG:
	default:
		mode |= fs.ModeIrregular
	}
	if m&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
