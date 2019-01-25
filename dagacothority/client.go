package dagacothority

import (
	"go.dedis.ch/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/student_18_daga/sign/daga"
	"github.com/satori/go.uuid"
)

// Client implements the daga.Client interface and embeds an onet.Client and whatever needed but is not needed by kyber.daga
type Client struct {
	daga.Client
	// TODO if time, one of the point of embedding anon interface is if you want to override some of the methods
	// (type has now access to a parent struct that implement interface and implements interface too through promotion), that was what I had in mind,
	// ideally would need to rewrite the daga functions to be methods, add them to the interface
	// and here override some of them where needed to wrap them in the onet framework
	// same mechanisms as extend / super in OO languages
	// + by doing so can pass any struct that implement daga.Client when creating Client => can test/mock/stub etc..
	Onet *onet.Client
}

// NewClient is used to initialize a new Client with a given index
// If no private key is given, a random one is chosen
func NewClient(i int, s kyber.Scalar) (*Client, error) {
	if dagaClient, err := daga.NewClient(suite, i, s); err != nil {
		return nil, err
	} else {
		return &Client{
			Client: dagaClient,
			Onet:   onet.NewClient(suite, ServiceName),
		}, nil
	}
}

// AdminCLient is the client side struct used by 3rd-party services admins (!not daga node admin!) to call context management endpoints.
// TODO FIXME move elsewhere later or remove completely (used now to test api/cli)
type AdminCLient struct {
	// TODO PGP identity or whatever etc.. when we will authenticate/authorize those partners
	ServiceID ServiceID
	*onet.Client
}

// NewAdminClient is used to initialize a new AdminClient
func NewAdminClient() *AdminCLient {
	return &AdminCLient{Client: onet.NewClient(suite, ServiceName), ServiceID: ServiceID(uuid.Must(uuid.NewV4()))}
}
