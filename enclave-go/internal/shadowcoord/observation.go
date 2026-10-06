package shadowcoord

import "github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/shadowobserve"

type Mode = shadowobserve.Mode

const (
	Off              = shadowobserve.Off
	Shadow           = shadowobserve.Shadow
	MaxIdentities    = shadowobserve.MaxIdentities
	MaxBatch         = shadowobserve.MaxBatch
	MaxResponseBytes = shadowobserve.MaxResponseBytes
	RefreshPath      = shadowobserve.RefreshPath
)

type Identity = shadowobserve.Identity
type Result = shadowobserve.Result
type Miss = shadowobserve.Miss
type Record = shadowobserve.Record
type Decision = shadowobserve.Decision
type Execution = shadowobserve.Execution
type Route = shadowobserve.Route

var newID = shadowobserve.NewID
var miss = shadowobserve.NewMiss
