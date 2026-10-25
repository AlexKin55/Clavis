// Package fuse implements the Clavis secure FUSE filesystem: a directory
// with physically encrypted files is mirrored to a mount point, where
// reads and writes are decrypted/encrypted on the fly. Content on disk is
// never stored in plaintext.
//
// Two on-disk formats are supported:
//
//	v1: [header 32B][ciphertext]
//	v2: [header 88B][signature 66B][ciphertext]
package fuse

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/clavis/clavis/internal/crypto"
)

// HeaderSize is the on-disk header size of a v1 protected file.
const HeaderSize = crypto.HeaderSize

// ReaderKeyProvider resolves the owner's read-only key material for v2
// documents (AS + owner public signature key). The mode tells the provider
// how to resolve it: proxy (via the server) or e2e (direct exchange).
type ReaderKeyProvider interface {
	// ReaderKey returns the read-key (AS) and the owner's Ed25519 public
	// key for the given owner identifier and sharing mode.
	ReaderKey(ctx context.Context, ownerKeyID [16]byte, mode crypto.Mode) (readKey, ownerPub []byte, err error)
}

// secureFile is an opened protected file. Read and Write operate on the
// visible (plaintext) content on the fly.
type secureFile struct {
	mu sync.RWMutex
	f  *os.File

	// Layout for the on-disk representation.
	headerHeader   *crypto.DocumentHeader // v1 (nil in v2)
	headerV2       *crypto.HeaderV2       // v2 (nil in v1)
	headerSize     int64                  // 32 (v1) or 88 (v2)
	sigSize        int64                  // 0 (v1) or 66 (v2)
	cryptor        crypto.Cryptor
	sigBlock       []byte // v2: signature block content
	ownerPub       []byte // v2: owner public signature key
	needsSignature bool   // v2: sign on Release
	identity       *crypto.AgentIdentity
	selfAS         []byte // v2: own reader key (for re-encryption)
	changed        bool   // v2: content was written
}

// Read implements fs.FileReader: read ciphertext, decrypt on the fly.
// For v2 files a full read verifies the owner signature.
func (h *secureFile) Read(_ context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()

	visible := h.visibleSize()
	if off >= visible {
		return fuse.ReadResultData(nil), 0
	}
	n := int64(len(dest))
	if off+n > visible {
		n = visible - off
	}

	cipherText := make([]byte, n)
	rn, err := h.f.ReadAt(cipherText, h.headerSize+h.sigSize+off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, errno(err)
	}
	cipherText = cipherText[:rn]

	plain, err := h.cryptor.Decrypt(cipherText, off)
	if err != nil {
		return nil, syscall.EIO
	}

	// v2 integrity: verify the owner signature on a full read.
	if h.headerV2 != nil && off == 0 && n == visible && len(h.ownerPub) > 0 {
		if e := h.verifySignatureLocked(cipherText); e != 0 {
			return nil, e
		}
	}

	copy(dest, plain)
	return fuse.ReadResultData(plain), 0
}

// Write implements fs.FileWriter: encrypt and store at the visible offset.
func (h *secureFile) Write(_ context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := h.fillGapLocked(off); err != nil {
		return 0, errno(err)
	}

	cipherText, err := h.cryptor.Encrypt(data, off)
	if err != nil {
		return 0, syscall.EIO
	}
	n, err := h.f.WriteAt(cipherText, h.headerSize+h.sigSize+off)
	if err != nil {
		return 0, errno(err)
	}
	if n > 0 {
		h.changed = true
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

// Release implements fs.FileReleaser. For v2 documents it finalizes the
// owner signature and, when a foreign document was edited, re-encrypts
// the whole document to the current agent (ownership change).
func (h *secureFile) Release(_ context.Context) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.headerV2 != nil && h.identity != nil {
		foreign := h.headerV2.OwnerKeyID != h.identity.OwnerKeyID()
		if foreign && h.changed {
			if err := h.reencryptToSelfLocked(); err != nil {
				return errno(err)
			}
		}
		if h.needsSignature || (h.changed && !foreign) {
			if err := h.signLocked(); err != nil {
				h.needsSignature = false
				return errno(err)
			}
			h.needsSignature = false
		}
	}
	return errno(h.f.Close())
}

// reencryptToSelfLocked re-encrypts a foreign document under the
// current agent: new document key DK', new header with the editor's
// owner id, wrapped under the editor's reader key AS. The content is
// read in full; the signature is finalized right after (signLocked).
func (h *secureFile) reencryptToSelfLocked() error {
	visible := h.visibleSize()
	oldCipher := make([]byte, visible)
	if _, err := h.f.ReadAt(oldCipher, h.headerSize+h.sigSize); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	plain, err := h.cryptor.Decrypt(oldCipher, 0)
	if err != nil {
		return err
	}

	dkNew := make([]byte, 32)
	if _, err := rand.Read(dkNew); err != nil {
		return err
	}
	var nonceNew [8]byte
	if _, err := rand.Read(nonceNew[:]); err != nil {
		return err
	}
	cryptorNew, err := crypto.NewAesCtr(dkNew, nonceNew)
	if err != nil {
		return err
	}
	cipherNew, err := cryptorNew.Encrypt(plain, 0)
	if err != nil {
		return err
	}
	if len(cipherNew) != len(oldCipher) {
		return fmt.Errorf("fuse: re-encryption length mismatch")
	}

	wrapped, err := crypto.WrapKey(h.selfAS, dkNew)
	if err != nil {
		return err
	}
	var wrappedDK [crypto.WrappedKeySize]byte
	copy(wrappedDK[:], wrapped)

	headerNew, err := crypto.NewHeaderV2(h.identity.OwnerKeyID(), h.headerV2.UUID, h.headerV2.Mode, nonceNew, wrappedDK)
	if err != nil {
		return err
	}
	sigBlock := make([]byte, crypto.SignatureBlockLen)

	physical := make([]byte, 0, int(h.headerSize)+int(h.sigSize)+len(cipherNew))
	physical = append(physical, headerNew.Encode()...)
	physical = append(physical, sigBlock...)
	physical = append(physical, cipherNew...)
	if _, err := h.f.WriteAt(physical, 0); err != nil {
		return err
	}

	h.headerV2 = headerNew
	h.cryptor = cryptorNew
	h.sigBlock = sigBlock
	h.ownerPub = nil
	h.needsSignature = true
	return nil
}

// truncateToVisible resizes the payload to size, keeping layout intact.
func (h *secureFile) truncateToVisible(size int64) syscall.Errno {
	h.mu.Lock()
	defer h.mu.Unlock()

	current := h.visibleSize()
	if size <= current {
		if err := h.f.Truncate(h.headerSize + h.sigSize + size); err != nil {
			return errno(err)
		}
		return 0
	}
	if err := h.fillGapLocked(size); err != nil {
		return errno(err)
	}
	return 0
}

// visibleSize returns the current payload size.
func (h *secureFile) visibleSize() int64 {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(h.f.Fd()), &st); err != nil {
		return 0
	}
	size := st.Size - h.headerSize - h.sigSize
	if size < 0 {
		return 0
	}
	return size
}

// fillGapLocked materializes encrypted zeros up to endVisible.
// The caller must hold h.mu.
func (h *secureFile) fillGapLocked(endVisible int64) error {
	current := h.visibleSize()
	if endVisible <= current {
		return nil
	}
	zeros := make([]byte, endVisible-current)
	cipher, err := h.cryptor.Encrypt(zeros, current)
	if err != nil {
		return err
	}
	if _, err := h.f.WriteAt(cipher, h.headerSize+h.sigSize+current); err != nil {
		return err
	}
	return nil
}

// verifySignatureLocked verifies the owner signature over the ciphertext.
func (h *secureFile) verifySignatureLocked(ciphertext []byte) syscall.Errno {
	payload := signaturePayloadForV2(h.headerV2, ciphertext)
	if !crypto.VerifySignature(h.ownerPub, payload, h.signatureBytes()) {
		return syscall.EACCES
	}
	return 0
}

// signLocked computes and stores the signature block for a finished v2
// file (called from Release).
func (h *secureFile) signLocked() error {
	visible := h.visibleSize()
	cipher := make([]byte, visible)
	if _, err := h.f.ReadAt(cipher, h.headerSize+h.sigSize); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	block := crypto.SignatureBlock(h.headerV2, h.identity, cipher)
	if _, err := h.f.WriteAt(block, h.headerSize); err != nil {
		return err
	}
	h.sigBlock = block
	return nil
}

func (h *secureFile) signatureBytes() []byte {
	if len(h.sigBlock) >= crypto.MetaSigLenBytes {
		return h.sigBlock[crypto.MetaSigLenBytes:]
	}
	return nil
}

// createProtectedFile creates a protected file, choosing the format based
// on the configuration (v2 when the identity is available).
func (r *SecureRoot) createProtectedFile(ctx context.Context, path string, mode uint32) (*secureFile, error) {
	if r.cfg.Identity != nil && len(r.cfg.ServerPub) > 0 && len(r.cfg.ServerNonce) > 0 {
		return r.createProtectedFileV2(ctx, path, mode)
	}
	return r.createProtectedFileV1(ctx, path, mode)
}

func (r *SecureRoot) createProtectedFileV1(ctx context.Context, path string, mode uint32) (*secureFile, error) {
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

	file, err := newFileHandleV1(ctx, r, osf, header)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	return file, nil
}

// createProtectedFileV2 creates a v2 document: fresh DK wrapped under the
// owner's reader key AS, owner-key header and a placeholder signature that
// is finalized on Release.
func (r *SecureRoot) createProtectedFileV2(_ context.Context, path string, mode uint32) (*secureFile, error) {
	identity := r.cfg.Identity
	osf, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.FileMode(mode))
	if err != nil {
		return nil, err
	}

	uuid, err := crypto.NewUUID()
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	dk := make([]byte, 32)
	if _, err := rand.Read(dk); err != nil {
		_ = osf.Close()
		return nil, err
	}
	var docNonce [8]byte
	if _, err := rand.Read(docNonce[:]); err != nil {
		_ = osf.Close()
		return nil, err
	}
	readerKey, err := identity.UnifiedReaderKey()
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	wrapped, err := crypto.WrapKey(readerKey, dk)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	var wrappedDK [crypto.WrappedKeySize]byte
	copy(wrappedDK[:], wrapped)

	modeFlag := r.cfg.DefaultMode
	if r.cfg.ModeProvider != nil {
		modeFlag = r.cfg.ModeProvider()
	}
	if modeFlag == 0 {
		modeFlag = crypto.ModeProxy
	}
	header, err := crypto.NewHeaderV2(identity.OwnerKeyID(), uuid, modeFlag, docNonce, wrappedDK)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}

	// Placeholder signature block; finalized at Release.
	sigBlock := make([]byte, crypto.SignatureBlockLen)
	physical := make([]byte, 0, crypto.HeaderV2Size+crypto.SignatureBlockLen)
	physical = append(physical, header.Encode()...)
	physical = append(physical, sigBlock...)
	if _, err := osf.WriteAt(physical, 0); err != nil {
		_ = osf.Close()
		return nil, err
	}

	cryptor, err := crypto.NewAesCtr(dk, docNonce)
	if err != nil {
		_ = osf.Close()
		return nil, err
	}
	return &secureFile{
		f:              osf,
		headerV2:       header,
		headerSize:     crypto.HeaderV2Size,
		sigSize:        crypto.SignatureBlockLen,
		cryptor:        cryptor,
		needsSignature: true,
		identity:       identity,
		selfAS:         readerKey,
	}, nil
}

// openProtectedFile opens a protected file, detecting the format version.
func (r *SecureRoot) openProtectedFile(ctx context.Context, path string, flags int) (*secureFile, error) {
	osf, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}

	// The header version lives at offset 4 (after the 4-byte magic).
	probe := make([]byte, 5)
	if _, err := io.ReadFull(osf, probe); err != nil {
		_ = osf.Close()
		return nil, fmt.Errorf("read header of %q: %w", path, err)
	}
	if _, err := osf.Seek(0, io.SeekStart); err != nil {
		_ = osf.Close()
		return nil, err
	}

	if probe[4] == crypto.HeaderVersion+1 {
		file, err := r.openProtectedFileV2(ctx, osf, path)
		if err != nil {
			_ = osf.Close()
			return nil, err
		}
		return file, nil
	}
	return r.openProtectedFileV1(ctx, osf, path)
}

func (r *SecureRoot) openProtectedFileV1(ctx context.Context, osf *os.File, path string) (*secureFile, error) {
	headerBytes := make([]byte, crypto.HeaderSize)
	if _, err := io.ReadFull(osf, headerBytes); err != nil {
		return nil, fmt.Errorf("read v1 header: %w", err)
	}
	header, err := crypto.ParseHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	file, err := newFileHandleV1(ctx, r, osf, header)
	if err != nil {
		r.notifyOpenFailure(path, err)
	}
	return file, err
}

func (r *SecureRoot) openProtectedFileV2(ctx context.Context, osf *os.File, path string) (*secureFile, error) {
	headerBytes := make([]byte, crypto.HeaderV2Size)
	if _, err := io.ReadFull(osf, headerBytes); err != nil {
		return nil, fmt.Errorf("read v2 header: %w", err)
	}
	header, err := crypto.ParseHeaderV2(headerBytes)
	if err != nil {
		return nil, err
	}
	if r.cfg.ReaderKeys == nil {
		return nil, errors.New("fuse: reader key provider not configured")
	}
	readKey, ownerPub, err := r.cfg.ReaderKeys.ReaderKey(ctx, header.OwnerKeyID, header.Mode)
	if err != nil {
		r.notifyOpenFailure(path, err)
		return nil, err
	}
	dk, err := crypto.UnwrapKey(readKey, header.WrappedDK[:])
	if err != nil {
		err = fmt.Errorf("fuse: unwrap document key: %w", err)
		r.notifyOpenFailure(path, err)
		return nil, err
	}
	cryptor, err := crypto.NewAesCtr(dk, header.Nonce)
	if err != nil {
		return nil, err
	}

	sigBlock := make([]byte, crypto.SignatureBlockLen)
	if _, err := io.ReadFull(osf, sigBlock); err != nil {
		return nil, fmt.Errorf("read signature block: %w", err)
	}

	// The editor's own reader key, needed to re-encrypt on ownership change.
	var selfAS []byte
	if r.cfg.Identity != nil && len(r.cfg.ServerPub) > 0 && len(r.cfg.ServerNonce) > 0 {
		selfAS, _ = r.cfg.Identity.UnifiedReaderKey()
	}

	return &secureFile{
		f:          osf,
		headerV2:   header,
		headerSize: crypto.HeaderV2Size,
		sigSize:    crypto.SignatureBlockLen,
		cryptor:    cryptor,
		sigBlock:   sigBlock,
		ownerPub:   ownerPub,
		identity:   r.cfg.Identity,
		selfAS:     selfAS,
	}, nil
}

func newFileHandleV1(ctx context.Context, r *SecureRoot, osf *os.File, header *crypto.DocumentHeader) (*secureFile, error) {
	key, err := r.cfg.KeyGetter.LoadKey(ctx, header.UUID)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	cryptor, err := crypto.NewCryptor(header, key)
	if err != nil {
		return nil, err
	}
	return &secureFile{
		f:            osf,
		headerHeader: header,
		headerSize:   crypto.HeaderSize,
		cryptor:      cryptor,
	}, nil
}

// notifyOpenFailure forwards key-related open failures to the Notifier.
func (r *SecureRoot) notifyOpenFailure(path string, err error) {
	if n := r.cfg.Notifier; n != nil {
		n.OpenFailed(path, err)
	}
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

// signaturePayloadForV2 mirrors crypto.signaturePayload.
func signaturePayloadForV2(h *crypto.HeaderV2, ciphertext []byte) []byte {
	header := h.Encode()
	digest := sha256sum(ciphertext)
	payload := make([]byte, 0, len(header)+len(digest))
	payload = append(payload, header...)
	payload = append(payload, digest...)
	return payload
}

func sha256sum(b []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}
