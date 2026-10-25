package fuse

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/clavis/clavis/internal/crypto"
)

// MountConfig holds the parameters required to mount the secure filesystem.
type MountConfig struct {
	// SourceDir is the physical directory with the encrypted files.
	SourceDir string
	// MountPoint is where the decrypted view is mounted.
	MountPoint string
	// Options are raw FUSE options (e.g. -f -d -o auto_unmount,allow_other).
	Options []string
	// KeyGetter provides key material for documents.
	KeyGetter crypto.KeyGetter
	// Logger is used for debugging output; may be nil.
	Logger *slog.Logger
}

// Mount mounts the secure filesystem and starts serving requests.
// The returned server must be unmounted with Unmount on shutdown.
func Mount(cfg MountConfig) (*fuse.Server, error) {
	mountOpts, err := parseMountOptions(cfg.Options)
	if err != nil {
		return nil, err
	}
	mountOpts.FsName = "clavis"
	mountOpts.Name = "clavis"
	mountOpts.DisableXAttrs = true

	root := NewSecureRoot(&Config{
		SourceDir: cfg.SourceDir,
		KeyGetter: cfg.KeyGetter,
		Logger:    cfg.Logger,
	})

	server, err := fs.Mount(cfg.MountPoint, root.rootNode(), &fs.Options{MountOptions: mountOpts})
	if err != nil {
		return nil, fmt.Errorf("mount %q: %w", cfg.MountPoint, err)
	}

	if cfg.Logger != nil {
		cfg.Logger.Info("fuse mounted",
			"mount_point", cfg.MountPoint,
			"source_dir", cfg.SourceDir,
		)
	}
	return server, nil
}

// Unmount safely unmounts the filesystem.
func Unmount(server *fuse.Server) error {
	if server == nil {
		return nil
	}
	return server.Unmount()
}

// parseMountOptions converts the raw option list (as used by the C++
// prototype) into go-fuse mount options. Supported tokens:
//
//	-f                     foreground — ignored (we run our own serve loop)
//	-d                     enable go-fuse debugging
//	-o op1,op2,...         comma separated options; allow_other and
//	                       auto_unmount are mapped to their dedicated fields
func parseMountOptions(raw []string) (fuse.MountOptions, error) {
	var mountOpts fuse.MountOptions
	var pass []string

	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case "-f":
			// Ignored: the serve loop runs in this process.
		case "-d":
			mountOpts.Debug = true
		case "-o":
			if i+1 >= len(raw) {
				return mountOpts, fmt.Errorf("missing value after -o")
			}
			i++
			for _, part := range strings.Split(raw[i], ",") {
				part = strings.TrimSpace(part)
				switch part {
				case "":
				case "allow_other":
					mountOpts.AllowOther = true
				case "auto_unmount":
					pass = append(pass, "auto_unmount")
				default:
					pass = append(pass, part)
				}
			}
		default:
			pass = append(pass, raw[i])
		}
	}

	mountOpts.Options = pass
	return mountOpts, nil
}
