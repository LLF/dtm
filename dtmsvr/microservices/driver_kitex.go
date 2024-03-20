package microservices

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/cloudwego/kitex/pkg/registry"
	"github.com/dtm-labs/dtmdriver"
	consul "github.com/kitex-contrib/registry-consul"
)

const (
	DriverName   = "dtm-driver-kitex"
	ConsulScheme = "consul"
)

type kitexDriver struct{}

func (k *kitexDriver) GetName() string {
	return DriverName
}

func (k *kitexDriver) RegisterAddrResolver() {

}

func (k *kitexDriver) RegisterService(target string, endpoint string) error {
	if target == "" {
		return nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return err
	}

	raddr, err := net.ResolveTCPAddr("tcp", endpoint)
	if err != nil {
		return err
	}
	info := &registry.Info{
		ServiceName: strings.TrimPrefix(u.Path, "/"),
		Addr:        raddr,
		Weight:      10,
	}

	switch u.Scheme {
	case ConsulScheme:
		r, err := consul.NewConsulRegister(u.Host)
		if err != nil {
			return err
		}
		return r.Register(info)
	default:
		return fmt.Errorf("unknown scheme: %s", u.Scheme)
	}
}

// const (
// 	dtmServer  = "etcd://localhost:2379/dtmservice"
// 	busiServer = "discovery://127.0.0.1:2379/trans/api.trans.v1.Trans/TransOut"
// )

func (k *kitexDriver) ParseServerMethod(uri string) (server string, method string, err error) {
	if !strings.Contains(uri, "//") {
		sep := strings.IndexByte(uri, '/')
		if sep == -1 {
			return "", "", fmt.Errorf("bad url: '%s'. no '/' found", uri)
		}
		return uri[:sep], uri[sep:], nil

	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", nil
	}
	index := strings.IndexByte(u.Path[1:], '/') + 1
	return u.Scheme + "://" + u.Host + u.Path[:index], u.Path[index:], nil
}

func init() {
	dtmdriver.Register(&kitexDriver{})

	// addr, err := net.ResolveTCPAddr("tcp", ":")
	// if err != nil {
	// 	return
	// }
	// l, err := net.ListenTCP("tcp", addr)
	// if err != nil {
	// 	return
	// }
	// defer l.Close()
	// config.Config.GrpcPort = int64(l.Addr().(*net.TCPAddr).Port)
}
