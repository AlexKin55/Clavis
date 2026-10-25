// Package fuse implements the Clavis secure FUSE filesystem: a directory
// with physically encrypted files (header + AES-CTR ciphertext) is mirrored
// to a mount point, where reads and writes are decrypted/encrypted on the
// fly. Content on disk is never stored in plaintext.
package fuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/clavis/clavis/internal/crypto"
)

// HeaderSize is the on-disk header size of a protected file.
// It is re-exported here so callers can distinguish the visible size
// of a file from its physical size.
const HeaderSize = crypto.HeaderSize

// secureFile is an opened protected file. Read and Write operate on the
// visible (plaintext) content on the fly: data is decrypted/encrypted
// against the physical file which stores the header followed by the
// ciphertext payload.
type secureFile struct {
	mu      sync.RWMutex
	f       *os.File
	header  *crypto.DocumentHeader
	cryptor crypto.Cryptor
}

// Read implements fs.FileReader: it reads ciphertext from the physical
// file (skipping the header) and decrypts it into the requested range.
func (h *secureFile) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()

	cipherText := make([]byte, len(dest))
	n, err := h.f.ReadAt(cipherText, HeaderSize+off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errno(err)
	}
	cipherText = cipherText[:n]

	plain, err := h.cryptor.Decrypt(cipherText, off)
	if err != nil {
		return nil, syscall.EIO
	}
	copy(dest, plain)
	return fuse.ReadResultData(plain), 0
}

// Write implements fs.FileWriter: it encrypts the plaintext and writes
// it into the physical file at the corresponding offset. A sparse gap
// between the current end of file and off is materialized with encrypted
// zeros so the hole does not read back as garbage.
func (h *secureFile) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.fillGap(off); err != nil {
		return 0, errno(err)
	}

	cipherText, err := h.cryptor.Encrypt(data, off)
	if err != nil {
		return 0, syscall.EIO
	}
	n, err := h.f.WriteAt(cipherText, HeaderSize+off)
	if err != nil {
		return 0, errno(err)
	}
	return uint32(n), 0
}

// Flush implements fs.FileFlusher.
func (h *secureFile) Flush(_ context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	return errno(h.f.Sync())
}

// Fsync implements fs.FileFsyncer.
func (h *secureFile) Fsync(_ context.Context, _ uint32) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	return errno(h.f.Sync())
}

// Release implements fs.FileReleaser.
func (h *secureFile) Release(_ context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()
	return errno(h.f.Close())
}

// truncateToVisible resizes the physical file to headerSize+size,
// keeping the header intact. Growing is done by materializing encrypted
// zeros so the added region reads back as zeros, not as keystream noise.
func (h *secureFile) truncateToVisible(size int64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()

	current := h.visibleSize()
	if size <= current {
		if err := h.f.Truncate(HeaderSize + size); err != nil {
			return errno(err)
		}
		return 0
	}
	if err := h.fillGap(size); err != nil {
		return errno(err)
	}
	return 0
}

// visibleSize returns the current payload size of the physical file.
func (h *secureFile) visibleSize() int64 {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(h.f.Fd()), &st); err != nil {
		return 0
	}
	size := st.Size - int64(HeaderSize)
	if size < 0 {
		return 0
	}
	return size
}

// fillGap materializes encrypted zeros between the current end of the
// payload and endVisible, so sparse holes read back as zeros.
func (h *secureFile) fillGap(endVisible int64) error {
	current := h.visibleSize()
	if endVisible <= current {
		return nil
	}
	zeros := make([]byte, endVisible-current)
	cipher, err := h.cryptor.Encrypt(zeros, current)
	if err != nil {
		return err
	}
	if _, err := h.f.WriteAt(cipher, HeaderSize+current); err != nil {
		return err
	}
	return nil
}

// createProtectedFile creates a new protected file: it generates a
// document UUID, writes the header and returns an opened secureFile.
func (r *SecureRoot) createProtectedFile(path string, mode uint32) (*secureFile, error) {
	osf, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.FileMode(mode))
	if err != nil {
		return nil, err
	}

	uuid, err := crypto.NewUUID()
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	header, err := crypto.NewHeader(uuid, crypto.AlgorithmAes256Ctr)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	if _, err := osf.WriteAt(header.Encode(), 0); err != nil {
		_ = osf.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}

	file, err := newFileHandle(r, osf, header)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	return file, nil
}

// openProtectedFile opens an existing protected file and resolves its
// header, nonce and cryptor.
func (r *SecureRoot) openProtectedFile(path string, flags int) (*secureFile, error) {
	osf, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}

	headerBytes := make([]byte, HeaderSize)
	if _, err := io.ReadFull(osf, headerBytes); err != nil {
		_ = osf.Close()
		return nil, fmt.Errorf("read header of %q: %w", path, err)
	}
	header, err := crypto.ParseHeader(headerBytes)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}

	// O_TRUNC must shrink the payload while the header stays intact.
	if flags&os.O_TRUNC != 0 {
		if err := osf.Truncate(HeaderSize); err != nil {
			_ = osf.Close()
			return nil, err
		}
		if _, err := osf.WriteAt(header.Encode(), 0); err != nil {
			_ = osf.Close()
			return nil, fmt.Errorf("rewrite header: %w", err)
		}
	}

	return newFileHandle(r, osf, header)
}

// newFileHandle resolves the key and builds the cryptor for the header.
func newFileHandle(r *SecureRoot, osf *os.File, header *crypto.DocumentHeader) (*secureFile, error) {
	key, err := r.cfg.KeyGetter.LoadKey(context.Background(), header.UUID)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	cryptor, err := crypto.NewCryptor(header, key)
	if err != nil {
		return nil, err
	}
	return &secureFile{f: osf, header: header, cryptor: cryptor}, nil
}

// errno converts a Go error into a FUSE errno.
func errno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errnoErr syscall.Errno
	if errors.As(err, &errnoErr) {
		return errnoErr
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return syscall.ENOENT
	case errors.Is(err, os.ErrPermission):
		return syscall.EACCES
	case errors.Is(err, os.ErrExist):
		return syscall.EEXIST
	case errors.Is(err, os.ErrInvalid):
		return syscall.EINVAL
	default:
		return syscall.EIO
	}
}
