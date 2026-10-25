// Package token provides hardware token access (PKCS#11) for the agent.
//
// A master AES wrapping key lives on the token. Each document key is
// wrapped into a blob which is stored next to the agent; the key material
// can be recovered only inside a logged-in token session ("the token is
// required for protected documents").
//
// The real backend uses github.com/miekg/pkcs11; an Unwrapper interface
// is exposed so the getter logic can be unit-tested without hardware.
package token

import (
	"fmt"
	"strings"

	p11 "github.com/miekg/pkcs11"
)

// wrapKeyLabel is the CKA_LABEL of the master wrapping key on the token.
// Overridable via Config.
const defaultWrapKeyLabel = "clavis-wrap"

// Config holds the PKCS#11 connection parameters.
type Config struct {
	// ModulePath is the PKCS#11 module (e.g. libsofthsm2.so).
	ModulePath string
	// TokenLabel selects the token by its label.
	TokenLabel string
	// PIN unlocks the token session (CKU_USER).
	PIN string
	// WrapKeyLabel is the CKA_LABEL of the master wrapping key.
	WrapKeyLabel string
	// GenerateWrapKey, when set, creates the master wrapping key on the
	// token if it does not exist yet (requires the SO/CKU rights).
	GenerateWrapKey bool
}

// Backend opens and uses a PKCS#11 token session.
type Backend struct {
	ctx       *p11.Ctx
	slot      uint
	wrapKey   p11.ObjectHandle
	wrapLabel []byte
}

// Unwrapper wraps and unwraps document key material with the token.
type Unwrapper interface {
	// Wrap protects the raw key with the token's wrapping key.
	Wrap(rawKey []byte) ([]byte, error)
	// Unwrap recovers the raw key from a token-protected blob.
	Unwrap(blob []byte) ([]byte, error)
	// Close releases the PKCS#11 context.
	Close() error
}

// Open connects to the module, selects the token and locates (or creates)
// the wrapping key. Failing any step makes the agent deny access, which is
// exactly the "token is required" policy.
func Open(cfg Config) (*Backend, error) {
	if cfg.WrapKeyLabel == "" {
		cfg.WrapKeyLabel = defaultWrapKeyLabel
	}

	ctx := p11.New(cfg.ModulePath)
	if ctx == nil {
		return nil, fmt.Errorf("token: cannot load module %q (CGO enabled build required)", cfg.ModulePath)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("token: initialize: %w", err)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, fmt.Errorf("token: slot list: %w", err)
	}
	slot := selectSlot(ctx, slots, cfg.TokenLabel)
	if slot == 0 {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("token: token %q not found", cfg.TokenLabel)
	}

	session, err := ctx.OpenSession(slot, p11.CKF_SERIAL_SESSION|p11.CKF_RW_SESSION)
	if err != nil {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("token: open session: %w", err)
	}
	defer func() {
		_ = ctx.CloseSession(session)
	}()

	if cfg.PIN != "" {
		if err := ctx.Login(session, p11.CKU_USER, cfg.PIN); err != nil {
			_ = ctx.Finalize()
			return nil, fmt.Errorf("token: login failed: %w", err)
		}
	}

	b := &Backend{ctx: ctx, slot: slot, wrapLabel: []byte(cfg.WrapKeyLabel)}
	wrapKey, err := b.findWrapKey(session, cfg.WrapKeyLabel)
	if err == nil && wrapKey == 0 && cfg.GenerateWrapKey {
		wrapKey, err = b.generateWrapKey(session, cfg.WrapKeyLabel)
	}
	if err != nil {
		_ = ctx.Finalize()
		return nil, err
	}
	if wrapKey == 0 {
		_ = ctx.Finalize()
		return nil, fmt.Errorf("token: wrapping key %q not found and generate_wrap_key is disabled", cfg.WrapKeyLabel)
	}
	b.wrapKey = wrapKey
	return b, nil
}

// Close implements Unwrapper.
func (b *Backend) Close() error {
	if b.ctx == nil {
		return nil
	}
	err := b.ctx.Finalize()
	b.ctx = nil
	return err
}

// Wrap implements Unwrapper: it imports the temporary key, wraps it with
// the master key and destroys the temporary object.
func (b *Backend) Wrap(rawKey []byte) ([]byte, error) {
	session, closer, err := b.newSession()
	if err != nil {
		return nil, err
	}
	defer closer()

	temp, err := b.ctx.CreateObject(session, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_VALUE, rawKey),
		p11.NewAttribute(p11.CKA_SENSITIVE, false),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_TOKEN, false),
	})
	if err != nil {
		return nil, fmt.Errorf("token: import key: %w", err)
	}
	defer func() {
		_ = b.ctx.DestroyObject(session, temp)
	}()

	blob, err := b.ctx.WrapKey(session, aesWrapMechanism(), b.wrapKey, temp)
	if err != nil {
		return nil, fmt.Errorf("token: wrap key: %w", err)
	}
	return blob, nil
}

// Unwrap implements Unwrapper: it unwraps the blob into a session key and
// reads its (temporarily extractable) value.
func (b *Backend) Unwrap(blob []byte) ([]byte, error) {
	session, closer, err := b.newSession()
	if err != nil {
		return nil, err
	}
	defer closer()

	h, err := b.ctx.UnwrapKey(session, aesWrapMechanism(), b.wrapKey, blob, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_SENSITIVE, false),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, true),
		p11.NewAttribute(p11.CKA_TOKEN, false),
	})
	if err != nil {
		return nil, fmt.Errorf("token: unwrap key failed (token required): %w", err)
	}
	defer func() {
		_ = b.ctx.DestroyObject(session, h)
	}()

	attrs, err := b.ctx.GetAttributeValue(session, h, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, fmt.Errorf("token: read unwrapped key: %w", err)
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return nil, fmt.Errorf("token: empty unwrapped key value")
	}
	return attrs[0].Value, nil
}

func (b *Backend) newSession() (p11.SessionHandle, func(), error) {
	session, err := b.ctx.OpenSession(b.slot, p11.CKF_SERIAL_SESSION)
	if err != nil {
		return 0, nil, fmt.Errorf("token: open session: %w", err)
	}
	return session, func() { _ = b.ctx.CloseSession(session) }, nil
}

func (b *Backend) findWrapKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	template := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_LABEL, label),
	}
	if err := b.ctx.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("token: find init: %w", err)
	}
	defer func() {
		_ = b.ctx.FindObjectsFinal(session)
	}()

	objs, _, err := b.ctx.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("token: find: %w", err)
	}
	if len(objs) == 0 {
		return 0, nil
	}
	return objs[0], nil
}

func (b *Backend) generateWrapKey(session p11.SessionHandle, label string) (p11.ObjectHandle, error) {
	h, err := b.ctx.GenerateKey(session, []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_GEN, nil)}, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_CLASS, p11.CKO_SECRET_KEY),
		p11.NewAttribute(p11.CKA_KEY_TYPE, p11.CKK_AES),
		p11.NewAttribute(p11.CKA_LABEL, label),
		p11.NewAttribute(p11.CKA_ENCRYPT, false),
		p11.NewAttribute(p11.CKA_DECRYPT, false),
		p11.NewAttribute(p11.CKA_WRAP, true),
		p11.NewAttribute(p11.CKA_UNWRAP, true),
		p11.NewAttribute(p11.CKA_SENSITIVE, true),
		p11.NewAttribute(p11.CKA_EXTRACTABLE, false),
		p11.NewAttribute(p11.CKA_TOKEN, true),
	})
	if err != nil {
		return 0, fmt.Errorf("token: generate wrapping key: %w", err)
	}
	return h, nil
}

func aesWrapMechanism() []*p11.Mechanism {
	return []*p11.Mechanism{p11.NewMechanism(p11.CKM_AES_KEY_WRAP, nil)}
}

// selectSlot returns the slot whose token label matches, or 0 otherwise.
// An empty label accepts the first token-present slot.
func selectSlot(ctx *p11.Ctx, slots []uint, tokenLabel string) uint {
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		label := strings.TrimRight(info.Label, "\x00")
		if tokenLabel == "" || label == tokenLabel {
			return slot
		}
	}
	return 0
}
