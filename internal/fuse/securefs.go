package fuse

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/clavis/clavis/internal/crypto"
	"github.com/clavis/clavis/internal/interceptor"
	"github.com/clavis/clavis/internal/subject"
)

// attrTimeout is the TTL for attributes and directory entries.
const attrTimeout = time.Second

// Config holds the parameters of the secure filesystem.
type Config struct {
	// SourceDir is the directory with the physically encrypted files.
	SourceDir string
	// KeyGetter provides the key material for v1 documents.
	KeyGetter crypto.KeyGetter
	// Interceptor, if set, decides whether the calling process may open
	// a document. A nil interceptor disables access control (tests/demo).
	Interceptor interceptor.Interceptor
	// Logger is used for debugging output; may be nil.
	Logger *slog.Logger

	// v2 fields: when Identity is set, new documents are created with the
	// v2 header (owner key, wrapped DK, signature).
	Identity    *crypto.AgentIdentity
	ServerPub   []byte
	ServerNonce []byte
	// DefaultMode is the sharing mode for new documents (Default: proxy).
	DefaultMode crypto.Mode
	// ReaderKeys resolves the owner's read-only key material for v2 reads.
	ReaderKeys ReaderKeyProvider
}

// SecureRoot holds the shared configuration of the filesystem.
type SecureRoot struct {
	cfg *Config
}

// NewSecureRoot creates the filesystem configuration holder and the root
// node for the mount.
func NewSecureRoot(cfg *Config) *SecureRoot {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SecureRoot{cfg: cfg}
}

// secureNode is any node of the mirrored tree (including the root).
// Directories and files are thin: the real state lives in the source
// directory.
type secureNode struct {
	fs.Inode
	root       *SecureRoot
	sourcePath string
}

// rootNode creates the node for the mount root.
func (r *SecureRoot) rootNode() *secureNode {
	node := &secureNode{root: r, sourcePath: r.cfg.SourceDir}
	r.cfg.Logger.Debug("secure fs initialized", "source_dir", r.cfg.SourceDir)
	return node
}

// Lookup resolves a child by name in the source directory.
func (n *secureNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	childPath := filepath.Join(n.sourcePath, name)
	var st syscall.Stat_t
	if err := syscall.Lstat(childPath, &st); err != nil {
		return nil, errno(err)
	}

	child := &secureNode{root: n.root, sourcePath: childPath}
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: st.Mode & syscall.S_IFMT})

	fillAttr(&out.Attr, &st, visibleSize(&st))
	out.SetEntryTimeout(attrTimeout)
	out.SetAttrTimeout(attrTimeout)
	return inode, 0
}

// Getattr reports the visible attributes: for files the size is reduced
// by the header size, so callers never see the ciphertext overhead.
func (n *secureNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	var st syscall.Stat_t
	if err := syscall.Lstat(n.sourcePath, &st); err != nil {
		return errno(err)
	}
	fillAttr(&out.Attr, &st, visibleSize(&st))
	out.SetTimeout(attrTimeout)
	return 0
}

// Open opens an existing protected file and returns a direct-IO handle.
// The calling process is identified, described and checked against the
// interceptor policy before the file is opened. The subject is attached
// to the context for the key getter.
func (n *secureNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	s := subjectInfoFromContext(ctx)
	s.FileName = n.sourcePath
	ctx = subject.WithContext(ctx, s)

	if n.root.cfg.Interceptor != nil {
		mask := interceptor.ReadMask
		if flags&syscall.O_ACCMODE != syscall.O_RDONLY {
			mask |= interceptor.WriteMask
		}
		if !n.root.cfg.Interceptor.Permit(mask, s) {
			n.root.cfg.Interceptor.LogAccess(s, false)
			return nil, 0, syscall.EACCES
		}
		n.root.cfg.Interceptor.LogAccess(s, true)
	}

	file, err := n.root.openProtectedFile(ctx, n.sourcePath, normalizeFlags(flags))
	if err != nil {
		n.root.cfg.Logger.Debug("open failed", "path", n.sourcePath, "error", err)
		return nil, 0, errno(err)
	}
	return file, fuse.FOPEN_DIRECT_IO, 0
}

// subjectInfoFromContext describes the process originated by the FUSE
// request. The PID comes from the kernel-provided caller; the executable
// name and credentials are enriched from /proc when the process is alive.
func subjectInfoFromContext(ctx context.Context) subject.Info {
	pid := 0
	var uid, gid uint32
	if fc, ok := ctx.(*fuse.Context); ok {
		pid = int(fc.Pid)
		uid, gid = fc.Uid, fc.Gid
	}

	s, err := subject.FromPID(pid)
	if err != nil {
		// The process may have exited; kernel credentials are still usable.
		return subject.Info{PID: pid, UID: uid, GID: gid}
	}
	s.UID, s.GID = uid, gid
	return s
}

// Create creates a new protected file with a fresh UUID and header.
// The calling process is checked against the interceptor before the file
// is created, so unauthorized applications cannot leave orphaned files.
func (n *secureNode) Create(ctx context.Context, name string, _ uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	path := filepath.Join(n.sourcePath, name)

	s := subjectInfoFromContext(ctx)
	s.FileName = path
	ctx = subject.WithContext(ctx, s)

	if n.root.cfg.Interceptor != nil {
		if !n.root.cfg.Interceptor.Permit(interceptor.WriteMask, s) {
			n.root.cfg.Interceptor.LogAccess(s, false)
			return nil, nil, 0, syscall.EACCES
		}
		n.root.cfg.Interceptor.LogAccess(s, true)
	}

	file, err := n.root.createProtectedFile(ctx, path, mode&0o7777)
	if err != nil {
		n.root.cfg.Logger.Debug("create failed", "path", path, "error", err)
		return nil, nil, 0, errno(err)
	}

	child := &secureNode{root: n.root, sourcePath: path}
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFREG})

	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return nil, nil, 0, errno(err)
	}
	fillAttr(&out.Attr, &st, visibleSize(&st))
	out.SetEntryTimeout(attrTimeout)
	out.SetAttrTimeout(attrTimeout)
	return inode, file, fuse.FOPEN_DIRECT_IO, 0
}

// Readdir lists the source directory entries.
func (n *secureNode) Readdir(_ context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := os.ReadDir(n.sourcePath)
	if err != nil {
		return nil, errno(err)
	}

	list := make([]fuse.DirEntry, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		st := info.Sys().(*syscall.Stat_t)
		list = append(list, fuse.DirEntry{
			Mode: st.Mode,
			Name: e.Name(),
			Ino:  st.Ino,
		})
	}
	return fs.NewListDirStream(list), 0
}

// Mkdir creates a directory in the source directory.
func (n *secureNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	path := filepath.Join(n.sourcePath, name)
	if err := os.Mkdir(path, os.FileMode(mode)&0o7777); err != nil {
		return nil, errno(err)
	}

	child := &secureNode{root: n.root, sourcePath: path}
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR})

	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return nil, errno(err)
	}
	fillAttr(&out.Attr, &st, visibleSize(&st))
	out.SetEntryTimeout(attrTimeout)
	out.SetAttrTimeout(attrTimeout)
	return inode, 0
}

// Unlink removes a file from the source directory.
func (n *secureNode) Unlink(_ context.Context, name string) syscall.Errno {
	return errno(os.Remove(filepath.Join(n.sourcePath, name)))
}

// Rmdir removes a directory from the source directory.
func (n *secureNode) Rmdir(_ context.Context, name string) syscall.Errno {
	return errno(os.Remove(filepath.Join(n.sourcePath, name)))
}

// Rename moves a file within the source tree.
func (n *secureNode) Rename(_ context.Context, name string, newParent fs.InodeEmbedder, newName string, _ uint32) syscall.Errno {
	parent, ok := newParent.(*secureNode)
	if !ok {
		return syscall.EXDEV
	}
	return errno(os.Rename(
		filepath.Join(n.sourcePath, name),
		filepath.Join(parent.sourcePath, newName),
	))
}

// Setattr applies size/mode/owner/timestamps changes to the source file.
func (n *secureNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if in.Valid&fuse.FATTR_SIZE != 0 {
		target := int64(in.Size)
		var e syscall.Errno
		if sf, ok := f.(*secureFile); ok {
			e = sf.truncateToVisible(target)
		} else {
			// No handle: reopen briefly so growth materializes zeros.
			ctx = subject.WithContext(ctx, subjectInfoFromContext(ctx))
			h, err := n.root.openProtectedFile(ctx, n.sourcePath, os.O_RDWR)
			if err != nil {
				return errno(err)
			}
			e = h.truncateToVisible(target)
			_ = h.Release(context.Background())
		}
		if e != 0 {
			return e
		}
	}
	if in.Valid&fuse.FATTR_MODE != 0 {
		if err := os.Chmod(n.sourcePath, os.FileMode(in.Mode)&0o7777); err != nil {
			return errno(err)
		}
	}
	if in.Valid&(fuse.FATTR_UID|fuse.FATTR_GID) != 0 {
		uid, gid := -1, -1
		if in.Valid&fuse.FATTR_UID != 0 {
			uid = int(in.Uid)
		}
		if in.Valid&fuse.FATTR_GID != 0 {
			gid = int(in.Gid)
		}
		if err := os.Chown(n.sourcePath, uid, gid); err != nil {
			return errno(err)
		}
	}
	if in.Valid&(fuse.FATTR_ATIME|fuse.FATTR_MTIME) != 0 {
		now := time.Now()
		atime, mtime := now, now
		if in.Valid&fuse.FATTR_ATIME != 0 {
			atime = time.Unix(int64(in.Atime), int64(in.Atimensec))
		}
		if in.Valid&fuse.FATTR_MTIME != 0 {
			mtime = time.Unix(int64(in.Mtime), int64(in.Mtimensec))
		}
		if err := os.Chtimes(n.sourcePath, atime, mtime); err != nil {
			return errno(err)
		}
	}

	var st syscall.Stat_t
	if err := syscall.Lstat(n.sourcePath, &st); err != nil {
		return errno(err)
	}
	fillAttr(&out.Attr, &st, visibleSize(&st))
	out.SetTimeout(attrTimeout)
	return 0
}

// visibleSize converts the physical file size into the visible size by
// subtracting the protected-file header.
func visibleSize(st *syscall.Stat_t) uint64 {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return uint64(st.Size)
	}
	physical := uint64(st.Size)
	if physical >= HeaderSize {
		return physical - HeaderSize
	}
	return 0
}

// fillAttr populates a FUSE attribute from the source stat. The caller
// passes the visible (already header-adjusted) size.
func fillAttr(out *fuse.Attr, st *syscall.Stat_t, size uint64) {
	out.Ino = st.Ino
	out.Size = size
	out.Blocks = (size + 511) / 512
	out.Atime = uint64(st.Atim.Sec)
	out.Atimensec = uint32(st.Atim.Nsec)
	out.Mtime = uint64(st.Mtim.Sec)
	out.Mtimensec = uint32(st.Mtim.Nsec)
	out.Ctime = uint64(st.Ctim.Sec)
	out.Ctimensec = uint32(st.Ctim.Nsec)
	out.Mode = st.Mode
	out.Nlink = uint32(st.Nlink)
	out.Uid = st.Uid
	out.Gid = st.Gid
	out.Rdev = uint32(st.Rdev)
	out.Blksize = uint32(st.Blksize)
}

// normalizeFlags mirrors the C++ prototype: a write-only open is upgraded
// to read-write so encryption state can be maintained.
func normalizeFlags(flags uint32) int {
	if flags&syscall.O_ACCMODE == syscall.O_WRONLY {
		flags = flags&^syscall.O_ACCMODE | uint32(os.O_RDWR)
	}
	return int(flags)
}
